import socket
import threading
import requests
import ssl
import hashlib
import base64
import struct
import secrets
import crypto.encryption as encryption

from data_models.transfer_file import TransferFile
from dataclasses import dataclass, asdict
from typing import Callable, Any
from io import BufferedWriter
from enum import Enum, auto
from pathlib import Path

from .connection_handler import ConnectionHandler

FILE_CHUNK_SIZE = 256 * 1024 # 256 KiB
MAX_MESSAGE_SIZE = 10 * 1024 * 1024  # 10 MiB

@dataclass
class NetworkEvent:
    type: str
    message: str | None = None
    details: str | None = None

class InboundState(Enum):
    IDLE = auto()
    METADATA_RECEIVED = auto()
    RECEIVING_FILE = auto()

class OutboundState(Enum):
    IDLE = auto()
    CONNECTING = auto()
    SENDING_FILE = auto()

class Network:
    def __init__(self):
        self._inbound_handler: ConnectionHandler | None = None
        self._outbound_handler: ConnectionHandler | None = None

        self._inbound_state: InboundState = InboundState.IDLE
        self._outbound_state: OutboundState = OutboundState.IDLE

        self._subscribers: list[Callable[[NetworkEvent], None]] = []

        self._accept_socket: socket.socket | None = None  # Used to listen for incoming connections
        self._accept_thread: threading.Thread | None = None  # Used for accepting connections

        self.host_port: int = 35555
        self.host_external_ip: str | None = None
        self.outbound_peer_public_ip: str | None = None
        self.inbound_peer_public_ip: str | None = None
        self.inbound_peer_fingerprint: str | None = None

        self._receiving_enabled: bool = False

        self.selected_file: TransferFile | None = None
        self.incoming_file: TransferFile | None = None
        self._incoming_file_handle: BufferedWriter | None = None
        self._received_file_data: int = 0
        self._last_file_data_progress_percentage: int = 0

    def initialize(self):
        self.host_external_ip = self._get_host_external_ip()

    def handle_incoming_message(self, conn: ConnectionHandler, msg_type: str, data: str, raw_payload: bytes):
        # If we haven't accepted the connection yet, don't handle any messages
        if not conn.accepted_conn:
            return

        if msg_type == "CONNECTION_RESPONSE":
            self._handle_connection_response(data)

        elif msg_type == "FILE_METADATA":
            self._on_file_metadata(data)

        elif msg_type == "FILE_CHUNK":
            self._on_file_chunk(raw_payload)

        elif msg_type == "FILE_DECISION":
            self._on_file_decision(data)

    ###############
    # EVENT STUFF #
    ###############

    def subscribe(self, callback: Callable[[NetworkEvent], None]):
        self._subscribers.append(callback)

    def _emit(self, event: NetworkEvent):
        for cb in self._subscribers:
            cb(event)

    ###################
    # SEND/RECV STUFF #
    ###################

    def send_msg(self, socket: socket.socket, msg: bytes):
        # Prefix each message with a 4-byte length
        msg_header = struct.pack('>I', len(msg))
        socket.sendall(msg_header + msg)

    def recv_msg(self, socket: socket.socket) -> bytes:
        # Read the 4-byte header to find out how long the message is
        header = self._recv_exact(socket, 4)
        msg_len = struct.unpack('>I', header)[0]

        if msg_len > MAX_MESSAGE_SIZE:
            raise ValueError(f"Message length {msg_len} exceeds limit of {MAX_MESSAGE_SIZE}")

        return self._recv_exact(socket, msg_len)

    def _recv_exact(self, socket: socket.socket, n_bytes: int) -> bytes:
        data = b""

        while len(data) < n_bytes:
            chunk = socket.recv(n_bytes - len(data))

            if not chunk:
                raise ConnectionError

            data += chunk

        return data

    ###################
    # RECEIVING STUFF #
    ###################

    def enable_receiving(self):
        if self._receiving_enabled:
            return

        self._accept_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._accept_socket.bind(("", self.host_port))
        self._accept_socket.listen(1)

        self._receiving_enabled = True

        self._accept_thread = threading.Thread(target=self._receive_connections, daemon=True)
        self._accept_thread.start()

    def disable_receiving(self) -> bool:
        if not self._receiving_enabled:
            return False

        self._receiving_enabled = False

        try:
            self._accept_socket.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass

        self._accept_socket.close()
        self._accept_thread.join()

        if self._inbound_handler:
            self._inbound_handler.stop()

        return True

    def _get_host_external_ip(self) -> str:
        try:
            # Use a public API to get the external IP address
            response = requests.get("https://api64.ipify.org?format=json")
            ip = response.json()["ip"]
            return ip
        except Exception:
            return "?"

    ####################
    # CONNECTION STUFF #
    ####################

    def _receive_connections(self):
        context = encryption.get_ssl_context(ssl.Purpose.CLIENT_AUTH)

        while self._receiving_enabled:
            try:
                newsocket, address = self._accept_socket.accept()
                ssl_socket = context.wrap_socket(newsocket, server_side=True)
                self.inbound_peer_public_ip = address[0]

                # We verify manually because if we use "ssl.CERT_REQUIRED" or "ssl.CERT_OPTIONAL",
                # we get CA errors. And if we use "ssl.NONE", the client won't send over their certificate.

                challenge = secrets.token_bytes(32)
                self.send_msg(ssl_socket, challenge)
                proof_bytes = self.recv_msg(ssl_socket)
                valid, fingerprint = encryption.verify_identity_proof(proof_bytes, challenge)

                if not valid:
                    self._close_socket(ssl_socket)
                    continue

                self.inbound_peer_fingerprint = fingerprint

                self._attach_connection(ssl_socket, is_outbound=False)
                self._emit(NetworkEvent("INBOUND_CONNECTION_REQUEST", "INCOMING"))
            except ConnectionError:
                self._handle_connection_error(False)
                break
            except Exception:
                if not self._receiving_enabled:
                    break

                self._emit(NetworkEvent("INBOUND_CONNECTION_REQUEST", "ERROR"))

    def accept_incoming_connection(self):
        if not self._inbound_handler:
            return

        if self._inbound_handler.accepted_conn:
            return

        self._inbound_handler.accepted_conn = True
        self._inbound_handler.send("CONNECTION_RESPONSE", "ACCEPTED")
        self._emit(NetworkEvent("INBOUND_CONNECTION_REQUEST", "ACCEPTED"))

    def decline_incoming_connection(self):
        if not self._inbound_handler:
            return

        if self._inbound_handler.accepted_conn:
            return

        # Handler stops itself when the peer client disconnects
        # TODO: Malicious peer could simply not disconnect and keep the connection open
        self._inbound_handler.send("CONNECTION_RESPONSE", "DECLINED")
        self._emit(NetworkEvent("INBOUND_CONNECTION_REQUEST", "DECLINED"))
        self._inbound_handler = None

    def _request_connection(self, ip: str, port: int, expected_fingerprint: str):
        try:
            context = encryption.get_ssl_context(ssl.Purpose.SERVER_AUTH)

            raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ssl_socket = context.wrap_socket(raw_socket, server_hostname=encryption.CERT_HOSTNAME)
            ssl_socket.connect((ip, port))

            # Fingerprint verification
            server_cert = ssl_socket.getpeercert(binary_form=True)
            server_fingerprint = hashlib.sha256(server_cert).digest()
            base64_server_fingerprint = base64.b64encode(server_fingerprint).decode("ascii")

            if base64_server_fingerprint != expected_fingerprint:
                self._close_socket(ssl_socket)
                raise ssl.SSLCertVerificationError("Fingerprint mismatch")

            # Send over proof
            challenge = self.recv_msg(ssl_socket)
            proof_payload = encryption.create_identity_proof(challenge)
            self.send_msg(ssl_socket, proof_payload)

            self.outbound_peer_public_ip = ip
            self._attach_connection(ssl_socket, is_outbound=True)
            self._outbound_handler.accepted_conn = True
        except ssl.SSLCertVerificationError:
            self._emit(NetworkEvent("OUTBOUND_CONNECTION_REQUEST", "INVALID_FINGERPRINT"))
        except Exception:
            self._emit(NetworkEvent("OUTBOUND_CONNECTION_REQUEST", "ERROR"))
        finally:
            self._outbound_state = OutboundState.IDLE

    def _handle_connection_response(self, data: str):
        if data == "ACCEPTED":
            self._emit(NetworkEvent("OUTBOUND_CONNECTION_REQUEST", "ACCEPTED"))
        else:
            self._outbound_handler.stop()
            self._outbound_handler = None
            self._emit(NetworkEvent("OUTBOUND_CONNECTION_REQUEST", "REFUSED"))

    def start_request_connection_thread(self, ip: str, port: int, expected_fingerprint: str) -> str:
        if self._outbound_state == OutboundState.CONNECTING:
            return "ALREADY_CONNECTING"
        elif self._outbound_state == OutboundState.SENDING_FILE:
            return "SENDING_FILES"
        elif self._inbound_state == InboundState.RECEIVING_FILE:
            return "RECEIVING_FILES"
        elif self._outbound_handler:
            return "ALREADY_CONNECTED"

        self._outbound_state = OutboundState.CONNECTING
        threading.Thread(target=self._request_connection, args=(ip, port, expected_fingerprint), daemon=True).start()
        return "STARTED"

    def break_connection(self) -> bool:
        if not self._outbound_handler:
            return False

        self._outbound_handler.stop()
        return True

    def _attach_connection(self, ssl_socket: ssl.SSLSocket, is_outbound: bool):
        handler = ConnectionHandler(
            ssl_socket,
            network=self,
            is_outbound=is_outbound
        )

        if is_outbound:
            self._outbound_handler = handler
        else:
            self._inbound_handler = handler

        handler.start()

    def _handle_connection_error(self, is_outbound: bool):
        event_msg = ""

        if is_outbound:
            self._outbound_handler = None
            self._outbound_state = OutboundState.IDLE
            event_msg = "OUTBOUND"
        else:
            self.incoming_file = None
            self._inbound_handler = None

            if self._incoming_file_handle is not None:
                self._incoming_file_handle.close()
                self._incoming_file_handle = None

            self._inbound_state = InboundState.IDLE
            event_msg = "INBOUND"

        self._emit(NetworkEvent("CONNECTION_LOST", event_msg))

    def _close_socket(self, sock: socket.socket):
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass

        try:
            sock.close()
        except Exception:
            pass

    ##############
    # FILE STUFF #
    ##############

    def _on_file_metadata(self, metadata: dict[str, Any]):
        if self._inbound_state != InboundState.IDLE:
            return

        self.incoming_file = TransferFile(**metadata)
        self._inbound_state = InboundState.METADATA_RECEIVED
        self._emit(NetworkEvent("FILE_RECEIVE", "METADATA_RECEIVED"))

    def decide_on_file(self, accept: bool) -> bool:
        if self._inbound_state != InboundState.METADATA_RECEIVED:
            return False

        if accept:
            self._received_file_data = 0
            self._last_file_data_progress_percentage = 0

            downloads = Path.home() / "Downloads"
            file_path = downloads / self.incoming_file.name
            self._incoming_file_handle = file_path.open("wb")

            self._inbound_state = InboundState.RECEIVING_FILE
            self._inbound_handler.send("FILE_DECISION", "ACCEPTED")
        else:
            self.incoming_file = None
            self._inbound_state = InboundState.IDLE
            self._inbound_handler.send("FILE_DECISION", "REJECTED")

        return True

    def _on_file_chunk(self, chunk: bytes):
        if self._inbound_state != InboundState.RECEIVING_FILE:
            return

        self._incoming_file_handle.write(chunk)
        self._received_file_data += len(chunk)

        # Update progress | Prevent emit spam
        progress_percentage = int((self._received_file_data / self.incoming_file.size) * 100)

        if progress_percentage != self._last_file_data_progress_percentage:
            self._emit(NetworkEvent("FILE_RECEIVE", "DATA_PROGRESS", str(progress_percentage)))
            self._last_file_data_progress_percentage = progress_percentage

        if self._received_file_data >= self.incoming_file.size:
            # Whole file is downloaded
            self._incoming_file_handle.close()
            self.incoming_file = None
            self._inbound_state = InboundState.IDLE
            self._emit(NetworkEvent("FILE_RECEIVE", "FINISHED"))

    def send_file_metadata(self):
        if self._outbound_state != OutboundState.IDLE or not self._outbound_handler or not self.selected_file:
            return False

        meta = asdict(self.selected_file)

        self._outbound_handler.send("FILE_METADATA", meta)
        self._outbound_state = OutboundState.SENDING_FILE
        return True

    def _on_file_decision(self, data: str):
        if data == "ACCEPTED":
            threading.Thread(target=self._send_file_chunks, daemon=True).start()
        else:
            self._outbound_state = OutboundState.IDLE

        self._emit(NetworkEvent("FILE_SEND", "FILE_DECISION", data))

    def _send_file_chunks(self):
        sent_data = 0
        last_percentage = 0

        with open(self.selected_file.path, "rb") as f:
            while chunk := f.read(FILE_CHUNK_SIZE):
                self._outbound_handler.send("FILE_CHUNK", None, chunk)
                sent_data += len(chunk)

                # Update progress | Prevent emit spam
                progress_percentage = int((sent_data / self.selected_file.size) * 100)

                if progress_percentage != last_percentage:
                    self._emit(NetworkEvent("FILE_SEND", "DATA_PROGRESS", str(progress_percentage)))
                    last_percentage = progress_percentage

        self._outbound_state = OutboundState.IDLE
        self._emit(NetworkEvent("FILE_SEND", "FINISHED"))

    def set_selected_file(self, path: str) -> str:
        if self._outbound_state != OutboundState.IDLE:
            return ""

        p = Path(path)

        file = TransferFile(
            path = path,
            name=p.name,
            size=p.stat().st_size,
        )

        self.selected_file = file
        return file.name

    ###############
    # OTHER STUFF #
    ###############

    def exit(self):
        self.disable_receiving()
        self.break_connection()
