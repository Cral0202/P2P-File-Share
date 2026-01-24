import json
import os
import socket
import threading
import time
import encryption
import requests
import miniupnpc
from PyQt6.QtCore import QObject, pyqtSignal
from models.transfer_file import TransferFile
from dataclasses import dataclass
from typing import Callable

CONFIRM_MSG = b"Confirm_" # The confirmation message
CONFIRMATION_MSG_SIZE = 8 # The size to use for confirmation messages
COMMON_MSG_SIZE = 256 # The size to use for most messages, e.g. metadata or keys
FILE_CHUNK_SIZE = 262144 # The size to use for file chunks
SERIALIZED_PUB_KEY_SIZE = 451 # The size of a serialized public key

@dataclass
class NetworkEvent:
    type: str
    message: str | None = None

class Network(QObject):
    receive_progress_bar_signal = pyqtSignal(int)  # The signal for the receive progress bar
    send_progress_bar_signal = pyqtSignal(int)  # The signal for the send progress bar
    spinner_signal = pyqtSignal(bool)  # The signal for the loading spinner
    outbound_connection_indicator_signal = pyqtSignal(bool)  # The signal for outbound connection indicators
    inbound_connection_indicator_signal = pyqtSignal(bool)  # The signal for inbound connection indicators
    file_sent_indicator_signal = pyqtSignal(bool)  # The signal for the file sent indicators
    sent_file_has_been_downloaded_signal = pyqtSignal(bool, str)  # The signal for if sent file has been downloaded
    file_ready_to_receive_signal = pyqtSignal(bool)  # The signal for files ready to be received
    reset_file_indicators_signal = pyqtSignal()  # The signal for resetting file indicators
    exception_signal = pyqtSignal(str)  # The signal for exceptions

    def __init__(self):
        super().__init__()

        self._subscribers: list[Callable[[NetworkEvent], None]] = []

        self._public_key = None
        self._private_key = None
        self._receiving_client_public_key = None  # The public RSA key of a receiving user
        self._sending_client_public_key = None  # The public RSA key of a sending user

        self._host_aes_key = os.urandom(16)  # Generate a random secret key (16 bytes for AES-128)
        self._host_aes_iv = os.urandom(16)  # Generate a random initialization vector (IV) for CBC mode (16 bytes)

        self._client_aes_key = None
        self._client_aes_iv = None

        self._host_socket = None  # The socket that clients connect to
        self._host_socket_gateway = None  # The communication object for the host socket
        self._client_socket = None  # The socket used for connecting to other users
        self._host_thread = None  # Used for accepting connections

        self.upnp_enabled = False  # True if UPNP is enabled on host network
        self._wan_ip_service = None  # The WAN IP service object of the igd (for UPNP)

        self.host_port = 35555  # Port which is opened and used
        self.host_external_ip = None  # The external ip of the host
        self.outbound_peer_public_ip = None  # The public ip of the outbound peer
        self.inbound_peer_public_ip = None  # The public ip of the inbound peer

        self._receiving_enabled = False  # True if receiving is enabled
        self._should_stop_receiving = False  # True if receiving should be stopped
        self.outbound_connection = False  # True if an outbound connection exists
        self._inbound_connection = False  # True if an inbound connection exists
        self._upnp_ports_open = False  # True if UPNP ports are open
        self._sending_files = False  # True if files are currently being sent
        self._receiving_files = False  # True if files are currently being received
        self._file_to_receive_exists = False  # True if there exists a file to receive
        self._trying_to_connect = False  # True if trying to connect to IP
        self._program_about_to_exit = False  # True if program is about to exit

        self.selected_file: TransferFile | None = None
        self.incoming_file: TransferFile | None = None

        self._metadata_event = threading.Event()  # Used to sleep and wake metadata thread
        self._accept_connections_event = threading.Event()  # Used to sleep and wake accept connections thread

    def initialize(self):
        self._wan_ip_service = self._get_wan_ip_service()
        self.host_external_ip = self._get_host_external_ip()
        self._public_key, self._private_key = encryption.generate_rsa_keys()

    def subscribe(self, callback):
        self._subscribers.append(callback)

    def _emit(self, event: NetworkEvent):
        for cb in self._subscribers:
            cb(event)

    # Makes sure data is received intact
    def _receive_intact_data(self, gateway: socket, length: int) -> bytes:
        data = b""

        while len(data) < length:
            data = data + gateway.recv(length)

            if not data:
                raise ConnectionError

        return data

    # Gets the service to use for WAN IP connections
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

    # Enables receiving
    def enable_receiving(self):
        if self._receiving_enabled:
            return

        if self.upnp_enabled and not self._upnp_ports_open:
            if not self._open_ports():
                return

        self._should_stop_receiving = False

        self._host_thread = threading.Thread(target=self._accept_connections)
        self._host_thread.daemon = True
        self._host_thread.start()

        self._receiving_enabled = True

    # Disables receiving
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
    def _open_ports(self) -> bool:
        try:
            # Opens the ports
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
                raise RuntimeError("UPnP port mapping failed")

            self._upnp_ports_open = True
            return True
        except Exception as e:
            if "ConflictInMappingEntry" in str(e) or 'refuse' in str(e).lower():
                self.exception_signal.emit(f"Error adding port mapping: Port may already be in use. Ports are not open")
            else:
                self.exception_signal.emit(f"Error adding port mapping: {e}. Ports are not open")

            return False

    # Closes the ports on the network
    def _close_ports(self):
        try:
            # Deletes the port mapping
            ok = self._wan_ip_service.deleteportmapping(
                self.host_port,  # external_port
                'TCP',           # protocol
                ''               # remote_host
            )

            if not ok:
                raise RuntimeError("UPnP port unmapping failed")

            self._upnp_ports_open = False
        except Exception as e:
            self.exception_signal.emit(f"An error occurred: {e} | Ports are not closed")

    # Accept connections from clients
    def _accept_connections(self):
        while not self._should_stop_receiving:
            try:
                if self._inbound_connection:
                    time.sleep(1)
                    continue

                self._accept_connections_event.clear()  # Clear the event since it may have been set

                self._host_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._host_socket.bind(("", self.host_port))
                self._host_socket.listen(1)

                client, address = self._host_socket.accept()

                self._host_socket_gateway = client
                self.inbound_peer_public_ip = address[0]

                # Exchange RSA keys
                serialized_sender_public_key = self._receive_intact_data(self._host_socket_gateway, SERIALIZED_PUB_KEY_SIZE)
                self._sending_client_public_key = encryption.rsa_deserialize_public_key(serialized_sender_public_key)

                serialized_user_public_key = encryption.rsa_serialize_public_key(self._public_key)
                self._host_socket_gateway.send(serialized_user_public_key)

                # Receive AES information and decrypt it
                encrypted_aes_key = self._receive_intact_data(self._host_socket_gateway, COMMON_MSG_SIZE)
                self._host_socket_gateway.send(CONFIRM_MSG)

                encrypted_aes_iv = self._receive_intact_data(self._host_socket_gateway, COMMON_MSG_SIZE)
                self._host_socket_gateway.send(CONFIRM_MSG)

                signature = self._receive_intact_data(self._host_socket_gateway, COMMON_MSG_SIZE)
                self._host_socket_gateway.send(CONFIRM_MSG)

                self._client_aes_key = encryption.rsa_decrypt(encrypted_aes_key, self._private_key)
                self._client_aes_iv = encryption.rsa_decrypt(encrypted_aes_iv, self._private_key)

                # Verify signature
                if not encryption.rsa_verify_signature(signature, self._client_aes_key, self._sending_client_public_key):
                    raise RuntimeError("Client AES key could not be verified")

                # Start the receive_metadata thread
                receive_metadata_thread = threading.Thread(target=self._receive_file_metadata)
                receive_metadata_thread.daemon = True
                receive_metadata_thread.start()

                self._host_socket.close()
                self._inbound_connection = True
                self.inbound_connection_indicator_signal.emit(True)

                self._accept_connections_event.wait()
            except ConnectionError:
                break
            except Exception as e:
                if self._should_stop_receiving:
                    break

                self._inbound_connection = False
                self.inbound_connection_indicator_signal.emit(False)
                self.exception_signal.emit(f"Error accepting connection: {e}")

    # Breaks the connection to the client
    def break_connection(self):
        if not self.outbound_connection:
            return

        try:
            if self._sending_files and not self._program_about_to_exit:
                raise RuntimeError("Cannot disconnect when currently sending files")
            if self._receiving_files and not self._program_about_to_exit:
                raise RuntimeError("Cannot disconnect when currently receiving files")

            # Close the client socket
            self._client_socket.close()
            self.outbound_connection = False
            self.outbound_connection_indicator_signal.emit(False)
        except Exception as e:
            self.exception_signal.emit(f"An error occurred: {e}")

    # Sends a connection request to specified IP
    def _request_connection(self, ip: str, port: int):
        try:
            if self._sending_files:
                raise RuntimeError("Cannot change connection when currently sending files")
            elif self._receiving_files:
                raise RuntimeError("Cannot change connection when currently receiving files")
            elif self.outbound_connection:
                raise RuntimeError("Cannot change connection when already connected")

            self.spinner_signal.emit(True)

            self._client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._client_socket.connect((ip, port))

            # Exchange RSA keys
            serialized_user_public_key = encryption.rsa_serialize_public_key(self._public_key)
            self._client_socket.send(serialized_user_public_key)

            serialized_receiver_public_key = self._receive_intact_data(self._client_socket, SERIALIZED_PUB_KEY_SIZE)
            self._receiving_client_public_key = encryption.rsa_deserialize_public_key(serialized_receiver_public_key)

            # Encrypt AES information and send it
            encrypted_aes_key = encryption.rsa_encrypt(self._host_aes_key, self._receiving_client_public_key)
            encrypted_aes_iv = encryption.rsa_encrypt(self._host_aes_iv, self._receiving_client_public_key)
            signature = encryption.rsa_sign(self._host_aes_key, self._private_key)

            self._client_socket.send(encrypted_aes_key)
            self._receive_intact_data(self._client_socket, CONFIRMATION_MSG_SIZE)

            self._client_socket.send(encrypted_aes_iv)
            self._receive_intact_data(self._client_socket, CONFIRMATION_MSG_SIZE)

            self._client_socket.send(signature)
            self._receive_intact_data(self._client_socket, CONFIRMATION_MSG_SIZE)

            self.outbound_peer_public_ip = ip
            self.outbound_connection = True
            self.outbound_connection_indicator_signal.emit(True)
        except ConnectionRefusedError:
            self.outbound_connection_indicator_signal.emit(False)
            self.exception_signal.emit(f"Connection to \"{ip}\" refused.")
        except RuntimeError as e:
            self.exception_signal.emit(f"{e}")
        except Exception as e:
            self.outbound_connection_indicator_signal.emit(False)
            self.exception_signal.emit(f"Could not connect to \"{ip}\"")
        finally:
            self._trying_to_connect = False
            self.spinner_signal.emit(False)

    # Gets the external IP of the host
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
        except Exception as e:
            self.exception_signal.emit(f"An error occurred: {e}")

    # Sends a file to the client
    def _send_file(self):
        try:
            self._send_file_metadata()
            response = self._receive_intact_data(self._client_socket, CONFIRMATION_MSG_SIZE).decode()

            if response == "Accepted":
                self.file_sent_indicator_signal.emit(False)
                self._send_file_data()
            elif response == "Rejected":
                self.sent_file_has_been_downloaded_signal.emit(False, self.selected_file.name)
                self.file_sent_indicator_signal.emit(False)
            else:
                raise ConnectionError

            self._sending_files = False
        except ConnectionError:
            self._handle_connection_error(True)
        except Exception as e:
            self.exception_signal.emit(f"An error occurred: {e}")
            self.file_sent_indicator_signal.emit(False)

    # Sends the metadata of a file
    def _send_file_metadata(self):
        try:
            metadata = {
                "file_name": self.selected_file.name,
                "file_size": self.selected_file.size,
            }
            metadata_json = json.dumps(metadata)

            encrypted_metadata = encryption.rsa_encrypt(metadata_json.encode(), self._receiving_client_public_key)
            signature = encryption.rsa_sign(metadata_json.encode(), self._private_key)

            # Send encrypted metadata and signature
            self._client_socket.send(encrypted_metadata)
            self._receive_intact_data(self._client_socket, CONFIRMATION_MSG_SIZE)

            self._client_socket.send(signature)
            self._receive_intact_data(self._client_socket, CONFIRMATION_MSG_SIZE)

            self.file_sent_indicator_signal.emit(True)
            self._receive_intact_data(self._client_socket, CONFIRMATION_MSG_SIZE)
        except ConnectionError:
            self._handle_connection_error(True)
        except Exception as e:
            self.exception_signal.emit(f"An error occurred: {e}")
            self.file_sent_indicator_signal.emit(False)

    # Sends the data of a file
    def _send_file_data(self):
        try:
            sent_data = 0

            with open(self.selected_file.path, "rb") as file:
                while sent_data < self.selected_file.size:
                    chunk = file.read(FILE_CHUNK_SIZE)

                    sent_data += len(chunk)

                    # Add padding if last chunk
                    if len(chunk) < FILE_CHUNK_SIZE:
                        chunk = encryption.aes_add_padding(chunk)

                    encrypted_chunk = encryption.aes_encrypt(chunk, self._host_aes_key, self._host_aes_iv)
                    self._client_socket.send(encrypted_chunk)

                    # Update the progress bar
                    progress_percentage = (sent_data / self.selected_file.size) * 100
                    self.send_progress_bar_signal.emit(int(progress_percentage))

                    self._receive_intact_data(self._client_socket, CONFIRMATION_MSG_SIZE)

            # Sync
            self._client_socket.send(CONFIRM_MSG)
            self._receive_intact_data(self._client_socket, CONFIRMATION_MSG_SIZE)

            self.sent_file_has_been_downloaded_signal.emit(True, self.selected_file.name)
        except ConnectionError:
            self._handle_connection_error(True)
        except Exception as e:
            self.exception_signal.emit(f"An error occurred: {e}")

    # Rejects a file
    def reject_file(self):
        if not self._file_to_receive_exists or self._receiving_files:
            return

        try:
            self._host_socket_gateway.send("Rejected".encode())
            self.file_ready_to_receive_signal.emit(False)
            self._file_to_receive_exists = False
            self._metadata_event.set()  # Indicate that new metadata can be received
        except ConnectionError:
            self._handle_connection_error(False)
        except Exception as e:
            self.exception_signal.emit(f"An error occurred: {e}")

    # Receives the metadata of a file
    def _receive_file_metadata(self):
        while self._host_socket_gateway and not self._program_about_to_exit:
            try:
                self._metadata_event.clear()  # Clear the event since it may have been set

                # Receive encrypted metadata and signature
                encrypted_metadata = self._receive_intact_data(self._host_socket_gateway, COMMON_MSG_SIZE)
                self._host_socket_gateway.send(CONFIRM_MSG)

                signature = self._receive_intact_data(self._host_socket_gateway, COMMON_MSG_SIZE)
                self._host_socket_gateway.send(CONFIRM_MSG)

                if not encrypted_metadata or not signature:
                    raise ConnectionError

                metadata_json = encryption.rsa_decrypt(encrypted_metadata, self._private_key).decode()

                # Verify signature
                if encryption.rsa_verify_signature(signature, metadata_json.encode(), self._sending_client_public_key):
                    metadata = json.loads(metadata_json)

                    file = TransferFile(
                        path = None,
                        name = metadata["file_name"],
                        size = metadata["file_size"],
                    )

                    self.incoming_file = file
                    self.file_ready_to_receive_signal.emit(True)

                    self._host_socket_gateway.send(CONFIRM_MSG)
                    self._file_to_receive_exists = True

                    self._metadata_event.wait()  # Block until there is new metadata to be received
                else:
                    raise RuntimeError("Metadata signature could not be verified")
            except ConnectionError:
                self._handle_connection_error(e, False)
                break
            except Exception as e:
                self.exception_signal.emit(f"An error occurred: {e}")
                break

    # Receives the data of a file
    def _receive_file_data(self):
        try:
            file_path = os.path.join(os.path.expanduser("~"), "Downloads", self.incoming_file.name)  # Get the download folder
            received_data = 0

            with open(file_path, "wb") as file:
                while received_data < self.incoming_file.size:
                    # Make sure chunk is received intact
                    data_left = self.incoming_file.size - received_data

                    if FILE_CHUNK_SIZE > data_left:
                        # Encrypted data is always a multiple of 16,
                        # and if already a multiple of 16, it gets 16 added to it
                        remainder = data_left % 16
                        length = (data_left - remainder) + 16

                        encrypted_chunk = self._receive_intact_data(self._host_socket_gateway, length)
                    else:
                        encrypted_chunk = self._receive_intact_data(self._host_socket_gateway, FILE_CHUNK_SIZE)

                    chunk = encryption.aes_decrypt(encrypted_chunk, self._client_aes_key, self._client_aes_iv)

                    # Remove padding if last chunk
                    if received_data + len(chunk) > self.incoming_file.size:
                        chunk = encryption.aes_remove_padding(chunk)

                    file.write(chunk)
                    received_data += len(chunk)

                    # Update the progress bar
                    progress_percentage = (received_data / self.incoming_file.size) * 100
                    self.receive_progress_bar_signal.emit(int(progress_percentage))

                    self._host_socket_gateway.send(CONFIRM_MSG)

            # Sync
            self._receive_intact_data(self._host_socket_gateway, CONFIRMATION_MSG_SIZE)
            self._host_socket_gateway.send(CONFIRM_MSG)

            self.file_ready_to_receive_signal.emit(False)
            self._file_to_receive_exists = False
            self._metadata_event.set()
        except ConnectionError:
                self._handle_connection_error(e, False)
        except Exception as e:
            self.exception_signal.emit(f"An error occurred: {e}")
        finally:
            self._receiving_files = False

    # Prepares the program for an exit
    def exit(self):
        self._program_about_to_exit = True
        self.disable_receiving()
        self.break_connection()

    def _handle_connection_error(self, is_outbound: bool):
        self.exception_signal.emit("An existing connection was terminated.")

        if is_outbound:
            self.outbound_connection = False
            self._sending_files = False
            self.file_sent_indicator_signal.emit(False)
            self.outbound_connection_indicator_signal.emit(False)
        else:
            self._file_to_receive_exists = False
            self._receiving_files = False
            self._inbound_connection = False
            self.inbound_connection_indicator_signal.emit(False)
            self.file_ready_to_receive_signal.emit(False)
            self._accept_connections_event.set()
            self._metadata_event.set()

    ###################
    # Thread starters #
    ###################

    # Starts the thread for receiving files
    def start_receive_file_thread(self):
        if self._receiving_files or not self._file_to_receive_exists:
            return

        try:
            self._receiving_files = True
            self._host_socket_gateway.send("Accepted".encode())
            receive_thread = threading.Thread(target=self._receive_file_data)
            receive_thread.daemon = True
            receive_thread.start()
        except ConnectionError:
            self._handle_connection_error(False)
        except Exception as e:
            self.exception_signal.emit(f"An error occurred: {e}")

    # Starts the request_connection thread
    def start_request_connection_thread(self, ip: str, port: int):
        if self._trying_to_connect:
            return

        self._trying_to_connect = True
        request_connection_thread = threading.Thread(target=self._request_connection, args=(ip, port))
        request_connection_thread.daemon = True
        request_connection_thread.start()

    # Starts the thread for sending files
    def start_send_file_thread(self):
        if self._sending_files or not self.outbound_connection or not self.selected_file:
            return

        self._sending_files = True
        self.reset_file_indicators_signal.emit()

        send_thread = threading.Thread(target=self._send_file)
        send_thread.daemon = True
        send_thread.start()
