import json
import os
import socket
import threading
import time
import requests
import miniupnpc
import ssl
import encryption
import hashlib
import base64
import struct
import secrets

from models.transfer_file import TransferFile
from dataclasses import dataclass, asdict
from typing import Callable

FILE_CHUNK_SIZE: int = 262144

@dataclass
class NetworkEvent:
    type: str
    message: str | None = None

class Network:
    def __init__(self):
        super().__init__()

        self._subscribers: list[Callable[[NetworkEvent], None]] = []

        self._host_socket: socket.socket | None = None  # The socket that users connect to
        self._host_socket_gateway: ssl.SSLSocket | None = None
        self._client_socket: ssl.SSLSocket | None = None  # The socket used for connecting to other users
        self._host_thread: threading.Thread | None = None  # Used for accepting connections

        self.upnp_enabled: bool = False
        self._wan_ip_service: miniupnpc.UPnP | None = None

        self.host_port: int = 35555
        self.host_external_ip: str | None = None
        self.outbound_peer_public_ip: str | None = None
        self.inbound_peer_public_ip: str | None = None
        self.inbound_peer_fingerprint: str | None = None

        self._receiving_enabled: bool = False
        self.outbound_connection: bool = False
        self._inbound_connection: bool = False
        self._incoming_connnection: bool = False
        self._upnp_ports_open: bool = False
        self._sending_files: bool = False
        self._receiving_files: bool = False
        self._trying_to_connect: bool = False
        self._program_about_to_exit: bool = False

        self.selected_file: TransferFile | None = None
        self.incoming_file: TransferFile | None = None

        self._metadata_event: threading.Event = threading.Event()  # Used to sleep and wake metadata thread
        self._accept_connections_event: threading.Event = threading.Event()  # Used to sleep and wake accept connections thread

    def initialize(self):
        self._wan_ip_service = self._get_wan_ip_service()
        self.host_external_ip = self._get_host_external_ip()

    def subscribe(self, callback):
        self._subscribers.append(callback)

    def _emit(self, event: NetworkEvent):
        for cb in self._subscribers:
            cb(event)

    def _send_msg(self, socket: socket.socket, msg: bytes):
        # Prefix each message with a 4-byte length
        msg_header = struct.pack('>I', len(msg))
        socket.sendall(msg_header + msg)

    def _recv_msg(self, socket: socket.socket) -> bytes:
        # Read the 4-byte header to find out how long the message is
        header = self._recv_exact(socket, 4)
        msg_len = struct.unpack('>I', header)[0]

        return self._recv_exact(socket, msg_len)

    def _recv_exact(self, socket: socket.socket, n_bytes: int) -> bytes:
        data = b""

        while len(data) < n_bytes:
            chunk = socket.recv(n_bytes - len(data))

            if not chunk:
                raise ConnectionError

            data += chunk

        return data

    def _get_wan_ip_service(self) -> miniupnpc.UPnP | None:
        try:
            u = miniupnpc.UPnP()
            num_devs = u.discover()

            if num_devs == 0:
                raise RuntimeError("No UPnP devices discovered on the network")

            u.selectigd()

            ext_ip = u.externalipaddress()

            if not ext_ip:
                raise RuntimeError("Failed to get external IP from IGD")

            self.upnp_enabled = True
            return u
        except Exception as e:
            self.upnp_enabled = False
            self._emit(NetworkEvent("UPNP_UNAVAILABLE", str(e)))
            return None

    def enable_receiving(self):
        if self._receiving_enabled:
            return

        if self.upnp_enabled and not self._upnp_ports_open:
            self._open_ports()

        self._host_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._host_socket.bind(("", self.host_port))
        self._host_socket.listen(1)

        self._receiving_enabled = True

        self._host_thread = threading.Thread(target=self._receive_connections, daemon=True)
        self._host_thread.start()

    def disable_receiving(self):
        if not self._receiving_enabled:
            return

        if self._sending_files and not self._program_about_to_exit:
            raise RuntimeError("Cannot disable receiving when currently sending files")
        if self._receiving_files and not self._program_about_to_exit:
            raise RuntimeError("Cannot disable receiving when currently receiving files")

        # TODO: Commented out block results in a weird state if connected while disabling receiving
        """ # Kill active inbound connection
        if self._inbound_connection:
            try:
                self._host_socket_gateway.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass

            try:
                self._host_socket_gateway.close()
            except Exception:
                pass

            self._inbound_connection = False """

        if self._upnp_ports_open:
            self._close_ports()

        self._receiving_enabled = False
        self._accept_connections_event.set()

        try:
            self._host_socket.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass

        self._host_socket.close()
        self._host_thread.join()

    # Opens ports on the network
    def _open_ports(self):
        ok = self._wan_ip_service.addportmapping(
            self.host_port,                             # external_port
            'TCP',                                      # protocol
            socket.gethostbyname(socket.gethostname()), # internal_client
            self.host_port,                             # internal_port
            'File Share',                               # description
            '',                                         # remote_host
            86400                                       # lease_duration
        )

        if not ok:
            raise RuntimeError("UPnP port mapping failed.")

        self._upnp_ports_open = True

    # Closes the ports on the network
    def _close_ports(self):
        ok = self._wan_ip_service.deleteportmapping(
            self.host_port,  # external_port
            'TCP',           # protocol
            ''               # remote_host
        )

        if not ok:
            raise RuntimeError("UPnP port unmapping failed. Ports are not closed.")

        self._upnp_ports_open = False

    def _get_host_external_ip(self) -> str:
        try:
            if self.upnp_enabled:
                ip = self._wan_ip_service.externalipaddress()
                return ip
            else:
                # Use a public API to get the external IP address
                response = requests.get("https://api64.ipify.org?format=json")
                ip = response.json()["ip"]
                return ip
        except Exception:
            return "?"

    def _receive_connections(self):
        context = encryption.get_ssl_context(ssl.Purpose.CLIENT_AUTH)

        while self._receiving_enabled:
            try:
                if self._inbound_connection:
                    time.sleep(1)
                    continue

                self._accept_connections_event.clear()  # Clear the event since it may have been set

                newsocket, address = self._host_socket.accept()
                self._host_socket_gateway = context.wrap_socket(newsocket, server_side=True)
                self.inbound_peer_public_ip = address[0]

                # We verify manually because if we use "ssl.CERT_REQUIRED" or "ssl.CERT_OPTIONAL",
                # we get CA errors. And if we use "ssl.NONE", the client won't send over their certificate.

                challenge = secrets.token_bytes(32)
                self._send_msg(self._host_socket_gateway, challenge)
                proof_bytes = self._recv_msg(self._host_socket_gateway)
                valid, fingerprint = encryption.verify_identity_proof(proof_bytes, challenge)

                if valid:
                    self.inbound_peer_fingerprint = fingerprint
                else:
                    self._close_socket(self._host_socket_gateway)
                    continue

                self._incoming_connnection = True
                self._inbound_connection = True
                self._emit(NetworkEvent("INBOUND_CONNECTION_REQUEST", "INCOMING"))
                self._accept_connections_event.wait()
            except ConnectionError:
                self._handle_connection_error(False)
                break
            except Exception:
                if not self._receiving_enabled:
                    break

                self._incoming_connnection = False
                self._inbound_connection = False
                self._emit(NetworkEvent("INBOUND_CONNECTION_REQUEST", "ERROR"))

    def accept_incoming_connection(self):
        if not self._incoming_connnection:
            return

        try:
            self._emit(NetworkEvent("INBOUND_CONNECTION_REQUEST", "ACCEPTED"))
            self._send_msg(self._host_socket_gateway, b"ACCEPTED")

            # Start the metadata thread
            threading.Thread(target=self._receive_file_metadata, daemon=True).start()
        except ConnectionError:
            self._handle_connection_error(False)
        finally:
            self._incoming_connnection = False

    def decline_incoming_connection(self):
        if not self._incoming_connnection:
            return

        try:
            self._emit(NetworkEvent("INBOUND_CONNECTION_REQUEST", "DECLINED"))
            self._send_msg(self._host_socket_gateway, b"DECLINED")
        except ConnectionError:
            self._handle_connection_error(False)
        finally:
            self._close_socket(self._host_socket_gateway)
            self._incoming_connnection = False
            self._inbound_connection = False
            self._accept_connections_event.set()

    def break_connection(self):
        if not self.outbound_connection:
            return

        if self._sending_files and not self._program_about_to_exit:
            raise RuntimeError("Cannot disconnect when currently sending files")
        elif self._receiving_files and not self._program_about_to_exit:
            raise RuntimeError("Cannot disconnect when currently receiving files")

        self._close_socket(self._client_socket)
        self.outbound_connection = False

    def _request_connection(self, ip: str, port: int, expected_fingerprint: str):
        try:
            event_msg = ""
            context = encryption.get_ssl_context(ssl.Purpose.SERVER_AUTH)

            raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._client_socket = context.wrap_socket(raw_socket, server_hostname=encryption.CERT_HOSTNAME)
            self._client_socket.connect((ip, port))

            # Fingerprint verification
            server_cert = self._client_socket.getpeercert(binary_form=True)
            server_fingerprint = hashlib.sha256(server_cert).digest()
            base64_server_fingerprint = base64.b64encode(server_fingerprint).decode("ascii")

            if base64_server_fingerprint != expected_fingerprint:
                self._close_socket(self._client_socket)
                raise ssl.SSLCertVerificationError("Fingerprint mismatch")

            # Send over proof
            challenge = self._recv_msg(self._client_socket)
            proof_payload = encryption.create_identity_proof(challenge)
            self._send_msg(self._client_socket, proof_payload)

            self.outbound_peer_public_ip = ip
            self.outbound_connection = True

            response = self._recv_msg(self._client_socket).decode()

            if response == "ACCEPTED":
                event_msg = "SUCCESS"
            else:
                raise ConnectionRefusedError # Raise since this error can also occur above
        except Exception as e:
            self.outbound_connection = False

            if isinstance(e, ssl.SSLCertVerificationError):
                event_msg = "INVALID_FINGERPRINT"
            elif isinstance(e, ConnectionRefusedError):
                event_msg = "CONNECTION_REFUSED"
            else:
                event_msg = "CONNECTION_ERROR"
        finally:
            self._trying_to_connect = False
            self._emit(NetworkEvent("OUTBOUND_CONNECTION_REQUEST", event_msg))

    def _send_file(self):
        try:
            event_msg = ""

            self._send_file_metadata()
            response = self._recv_msg(self._client_socket).decode()

            if response == "ACCEPTED":
                event_msg = "ACCEPTED"
                self._send_file_data()
            elif response == "REJECTED":
                event_msg = "REJECTED"
            else:
                raise ConnectionError
        except ConnectionError:
            self._handle_connection_error(True)
        except Exception:
            event_msg = "ERROR"
        finally:
            self._sending_files = False
            self._emit(NetworkEvent("FILE_SEND_FINISHED", event_msg))

    def _send_file_metadata(self):
        try:
            event_msg = ""
            metadata_json = json.dumps(asdict(self.selected_file)).encode()
            self._send_msg(self._client_socket, metadata_json)

            event_msg = "ACCEPTED"
        except ConnectionError:
            self._handle_connection_error(True)
        except Exception:
            event_msg = "ERROR"
        finally:
            self._emit(NetworkEvent("FILE_METADATA_SEND_FINISHED", event_msg))

    def _send_file_data(self):
        try:
            event_msg = ""
            sent_data = 0

            with open(self.selected_file.path, "rb") as file:
                while sent_data < self.selected_file.size:
                    chunk = file.read(FILE_CHUNK_SIZE)

                    if not chunk:
                        break

                    self._client_socket.sendall(chunk)
                    sent_data += len(chunk)

                    # Update progress
                    progress_percentage = int((sent_data / self.selected_file.size) * 100)
                    self._emit(NetworkEvent("FILE_DATA_SEND_PROGRESS", str(progress_percentage)))

            event_msg = "SUCCESS"
        except ConnectionError:
            self._handle_connection_error(True)
        except Exception:
            event_msg = "ERROR"
        finally:
            self._emit(NetworkEvent("FILE_DATA_SEND_FINISHED", event_msg))

    def reject_file(self) -> bool:
        if not self.incoming_file or self._receiving_files:
            return False

        try:
            self.incoming_file = None
            self._metadata_event.set()  # Indicate that new metadata can be received
            self._send_msg(self._host_socket_gateway, b"REJECTED")
            return True
        except ConnectionError:
            self._handle_connection_error(False)
            return True
        except Exception:
            raise

    def _receive_file_metadata(self):
        while self._inbound_connection and not self._program_about_to_exit:
            try:
                self._metadata_event.clear()  # Clear the event since it may have been set

                metadata_json = self._recv_msg(self._host_socket_gateway).decode()
                metadata = json.loads(metadata_json)

                self.incoming_file = TransferFile(**metadata)
                self._emit(NetworkEvent("FILE_METADATA_RECEIVE_FINISHED", "SUCCESS"))
                self._metadata_event.wait()
            except ConnectionError:
                self._handle_connection_error(False)
                break
            except Exception:
                self._emit(NetworkEvent("FILE_METADATA_RECEIVE_FINISHED", "ERROR"))
                break

    def _receive_file_data(self):
        try:
            event_msg = ""
            file_path = os.path.join(os.path.expanduser("~"), "Downloads", self.incoming_file.name)  # Get the download folder
            received_data = 0

            with open(file_path, "wb") as file:
                while received_data < self.incoming_file.size:
                    chunk = self._host_socket_gateway.recv(FILE_CHUNK_SIZE)

                    if not chunk:
                        raise ConnectionError

                    file.write(chunk)
                    received_data += len(chunk)

                    # Update progress
                    progress_percentage = int((received_data / self.incoming_file.size) * 100)
                    self._emit(NetworkEvent("FILE_DATA_RECEIVE_PROGRESS", str(progress_percentage)))

            event_msg = "SUCCESS"
            self.incoming_file = None
            self._metadata_event.set()
        except ConnectionError:
            event_msg = "PEER_DISCONNECTED"
            self._handle_connection_error(False)
        except Exception:
            event_msg = "ERROR"
        finally:
            self._emit(NetworkEvent("FILE_DATA_RECEIVE_FINISHED", event_msg))
            self._receiving_files = False

    # Prepares the program for an exit
    def exit(self):
        self._program_about_to_exit = True
        self.disable_receiving()
        self.break_connection()

    def _handle_connection_error(self, is_outbound: bool):
        event_msg = ""

        if is_outbound:
            self.outbound_connection = False
            self._sending_files = False
            event_msg = "OUTBOUND"
        else:
            self.incoming_file = None
            self._receiving_files = False
            self._inbound_connection = False
            self._accept_connections_event.set()
            self._metadata_event.set()
            event_msg = "INBOUND"

        self._emit(NetworkEvent("CONNECTION_LOST", event_msg))

    def set_selected_file(self, path: str) -> str:
        if self._sending_files:
            return ""

        file = TransferFile(
            path = path,
            name = os.path.basename(path),
            size = os.path.getsize(path),
        )

        self.selected_file = file
        return file.name

    def _close_socket(self, sock: socket.socket):
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass

        try:
            sock.close()
        except Exception:
            pass

    ###################
    # Thread starters #
    ###################

    def start_receive_file_thread(self):
        if self._receiving_files or not self.incoming_file:
            return

        try:
            self._receiving_files = True
            self._send_msg(self._host_socket_gateway, b"ACCEPTED")

            threading.Thread(target=self._receive_file_data, daemon=True).start()
        except ConnectionError:
            self._handle_connection_error(False)
        except Exception:
            raise

    def start_request_connection_thread(self, ip: str, port: int, expected_fingerprint) -> str:
        if self._trying_to_connect:
            return "ALREADY_CONNECTING"
        elif self._sending_files:
            return "SENDING_FILES"
        elif self._receiving_files:
            return "RECEIVING_FILES"
        elif self.outbound_connection:
            return "ALREADY_CONNECTED"

        self._trying_to_connect = True
        threading.Thread(target=self._request_connection, args=(ip, port, expected_fingerprint), daemon=True).start()
        return "STARTED"

    def start_send_file_thread(self) -> bool:
        if self._sending_files or not self.outbound_connection or not self.selected_file:
            return False

        self._sending_files = True

        threading.Thread(target=self._send_file, daemon=True).start()
        return True
