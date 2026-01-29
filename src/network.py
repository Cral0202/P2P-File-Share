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

from models.transfer_file import TransferFile
from dataclasses import dataclass, asdict
from typing import Callable

FILE_CHUNK_SIZE: int = 262144
METADATA_HEADER_SIZE: int = 4

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

        self._receiving_enabled: bool = False
        self._should_stop_receiving: bool = False
        self.outbound_connection: bool = False
        self._inbound_connection: bool = False
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

        self._should_stop_receiving = False

        self._host_thread = threading.Thread(target=self._accept_connections, daemon=True)
        self._host_thread.start()

        self._receiving_enabled = True

    def disable_receiving(self):
        if not self._receiving_enabled:
            return

        if self._sending_files and not self._program_about_to_exit:
            raise RuntimeError("Cannot disable receiving when currently sending files")
        if self._receiving_files and not self._program_about_to_exit:
            raise RuntimeError("Cannot disable receiving when currently receiving files")

        if self._upnp_ports_open:
            self._close_ports()

        self._should_stop_receiving = True

        self._accept_connections_event.set()

        try:
            self._host_socket.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass

        self._host_socket.close()
        self._host_thread.join()

        self._receiving_enabled = False

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

    def _accept_connections(self):
        context = encryption.get_ssl_context(ssl.Purpose.CLIENT_AUTH)

        self._host_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._host_socket.bind(("", self.host_port))
        self._host_socket.listen(1)

        while not self._should_stop_receiving:
            try:
                if self._inbound_connection:
                    time.sleep(1)
                    continue

                self._accept_connections_event.clear()  # Clear the event since it may have been set

                newsocket, address = self._host_socket.accept()
                self._host_socket_gateway = context.wrap_socket(newsocket, server_side=True)
                self.inbound_peer_public_ip = address[0]

                # Start the metadata thread
                thread = threading.Thread(target=self._receive_file_metadata, daemon=True)
                thread.start()

                self._inbound_connection = True
                self._emit(NetworkEvent("INBOUND_CONNECTION_REQUEST", "SUCCESS"))

                self._accept_connections_event.wait()
            except ConnectionError:
                break
            except Exception:
                if self._should_stop_receiving:
                    break

                self._inbound_connection = False
                self._emit(NetworkEvent("INBOUND_CONNECTION_REQUEST", "ERROR"))

    def break_connection(self):
        if not self.outbound_connection:
            return

        if self._sending_files and not self._program_about_to_exit:
            raise RuntimeError("Cannot disconnect when currently sending files")
        elif self._receiving_files and not self._program_about_to_exit:
            raise RuntimeError("Cannot disconnect when currently receiving files")

        self._client_socket.close()
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
                self._client_socket.close()
                raise ssl.SSLCertVerificationError("Fingerprint mismatch")

            self.outbound_peer_public_ip = ip
            self.outbound_connection = True
            event_msg = "SUCCESS"
        except ConnectionRefusedError:
            event_msg = "CONNECTION_REFUSED"
        except ssl.SSLCertVerificationError:
            event_msg = "INVALID_FINGERPRINT"
        except Exception:
            event_msg = "CONNECTION_ERROR"
        finally:
            self._trying_to_connect = False
            self._emit(NetworkEvent("OUTBOUND_CONNECTION_REQUEST", event_msg))

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

    def _send_file(self):
        try:
            event_msg = ""

            self._send_file_metadata()
            response = self._client_socket.recv(1024).decode().strip()

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

            # Send length first so receiver knows how much to read
            metadata_size = len(metadata_json).to_bytes(METADATA_HEADER_SIZE, byteorder='big')
            self._client_socket.sendall(metadata_size)
            self._client_socket.sendall(metadata_json)

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
            self._host_socket_gateway.sendall("REJECTED".encode())
            return True
        except ConnectionError:
            self._handle_connection_error(False)
            return True
        except Exception:
            raise

    def _receive_file_metadata(self):
        while self._host_socket_gateway and not self._program_about_to_exit:
            try:
                self._metadata_event.clear()  # Clear the event since it may have been set
                size_data = self._host_socket_gateway.recv(METADATA_HEADER_SIZE)

                if not size_data:
                    break

                metadata_size = int.from_bytes(size_data, byteorder='big')
                metadata_json = self._host_socket_gateway.recv(metadata_size).decode()
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
                        break

                    file.write(chunk)
                    received_data += len(chunk)

                    # Update progress
                    progress_percentage = int((received_data / self.incoming_file.size) * 100)
                    self._emit(NetworkEvent("FILE_DATA_RECEIVE_PROGRESS", str(progress_percentage)))

            event_msg = "SUCCESS"
            self.incoming_file = None
            self._metadata_event.set()
        except ConnectionError:
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
        file = TransferFile(
            path = path,
            name = os.path.basename(path),
            size = os.path.getsize(path),
        )

        self.selected_file = file
        return file.name

    ###################
    # Thread starters #
    ###################

    def start_receive_file_thread(self):
        if self._receiving_files or not self.incoming_file:
            return

        try:
            self._receiving_files = True
            self._host_socket_gateway.sendall("ACCEPTED".encode())

            thread = threading.Thread(target=self._receive_file_data, daemon=True)
            thread.start()
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
        thread = threading.Thread(target=self._request_connection, args=(ip, port, expected_fingerprint), daemon=True)
        thread.start()
        return "STARTED"

    def start_send_file_thread(self) -> bool:
        if self._sending_files or not self.outbound_connection or not self.selected_file:
            return False

        self._sending_files = True

        thread = threading.Thread(target=self._send_file, daemon=True)
        thread.start()
        return True
