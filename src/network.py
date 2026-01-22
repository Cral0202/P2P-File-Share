import json
import os
import socket
import threading
import time
import encryption

import requests
import miniupnpc
from PyQt6.QtCore import QObject, pyqtSignal

class Network(QObject):
    receive_progress_bar_signal = pyqtSignal(int)  # The signal for the receive progress bar
    send_progress_bar_signal = pyqtSignal(int)  # The signal for the send progress bar
    spinner_signal = pyqtSignal(bool)  # The signal for the loading spinner
    outbound_connection_indicator_signal = pyqtSignal(bool)  # The signal for outbound connection indicators
    inbound_connection_indicator_signal = pyqtSignal(bool)  # The signal for inbound connection indicators
    file_sent_indicator_signal = pyqtSignal(bool)  # The signal for the file sent indicators
    receiving_allowed_indicator_signal = pyqtSignal(bool)  # The signal for enabled/disabled receiving indicators
    sent_file_has_been_downloaded_signal = pyqtSignal(bool, str)  # The signal for if sent file has been downloaded
    file_ready_to_receive_signal = pyqtSignal(bool)  # The signal for files ready to be received
    reset_file_indicators_signal = pyqtSignal()  # The signal for resetting file indicators
    exception_signal = pyqtSignal(str)  # The signal for exceptions

    def __init__(self):
        super().__init__()

        self.public_key, self.private_key = encryption.generate_rsa_keys() # The host's private RSA key and public RSA key
        self.receiving_client_public_key = None  # The public RSA key of a receiving user
        self.sending_client_public_key = None  # The public RSA key of a sending user

        self.host_aes_key = os.urandom(16)  # Generate a random secret key (16 bytes for AES-128)
        self.host_aes_iv = os.urandom(16)  # Generate a random initialization vector (IV) for CBC mode (16 bytes)

        self.client_aes_key = None
        self.client_aes_iv = None

        self.host_socket = None  # The socket that clients connect to
        self.host_socket_gateway = None  # The communication object for the host socket
        self.client_socket = None  # The socket used for connecting to other users
        self.host_thread = None  # Used for accepting connections

        self.upnp_enabled = False  # True if UPNP is enabled on host network
        self.wan_ip_service = self.get_wan_ip_service()  # The WAN IP service object of the igd (for UPNP)

        self.host_port = 35555  # Port which is opened and used
        self.host_internal_ip = socket.gethostbyname(socket.gethostname())  # The internal ip of the host
        self.host_external_ip = self.get_host_external_ip()  # The external ip of the host
        self.outbound_peer_public_ip = None  # The public ip of the outbound peer
        self.inbound_peer_public_ip = None  # The public ip of the inbound peer

        self.receiving_enabled = False  # True if receiving is enabled
        self.should_stop_receiving = False  # True if receiving should be stopped
        self.outbound_connection = False  # True if an outbound connection exists
        self.inbound_connection = False  # True if an inbound connection exists
        self.upnp_ports_open = False  # True if UPNP ports are open
        self.sending_files = False  # True if files are currently being sent
        self.receiving_files = False  # True if files are currently being received
        self.file_to_receive_exists = False  # True if there exists a file to receive
        self.trying_to_connect = False  # True if trying to connect to IP
        self.program_about_to_exit = False  # True if program is about to exit

        self.file_to_be_received_name = None  # The name of the file ready to be received
        self.file_to_be_received_size = None  # The size of the file ready to be received

        self.confirm_message = b"Confirm_"  # The confirmation message
        self.confirmation_message_size = 8  # The size to use for confirmation messages
        self.common_message_size = 256  # The size to use for most messages, e.g. metadata or keys
        self.file_chunk_size = 262144  # The size to use for file chunks
        self.serialized_public_key_size = 451  # The size of a serialized public key

        self.metadata_event = threading.Event()  # Used to sleep and wake metadata thread
        self.accept_connections_event = threading.Event()  # Used to sleep and wake accept connections thread

    # Makes sure the data is received intact
    def receive_intact_data(self, gateway: socket, length: int) -> bytes:
        data = b""

        while len(data) < length:
            data = data + gateway.recv(length)

            if not data:
                raise ConnectionError

        return data

    # Gets the service to use for WAN IP connections
    def get_wan_ip_service(self) -> miniupnpc.UPnP | None:
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
            self.exception_signal.emit(f"An error occurred: {e}")
            return None

    # Enables receiving
    def enable_receiving(self):
        if self.receiving_enabled:
            return

        try:
            if self.upnp_enabled and not self.upnp_ports_open:
                if not self.open_ports():
                    return

            self.should_stop_receiving = False

            self.host_thread = threading.Thread(target=self.accept_connections)
            self.host_thread.daemon = True
            self.host_thread.start()

            self.receiving_enabled = True
            self.receiving_allowed_indicator_signal.emit(True)
        except Exception as e:
            self.exception_signal.emit(f"An error occurred: {e}")

    # Disables receiving
    def disable_receiving(self):
        if not self.receiving_enabled:
            return

        try:
            if self.sending_files and not self.program_about_to_exit:
                raise RuntimeError("Cannot disable receiving when currently sending files")
            if self.receiving_files and not self.program_about_to_exit:
                raise RuntimeError("Cannot disable receiving when currently receiving files")

            if self.upnp_ports_open:
                self.close_ports()

            self.should_stop_receiving = True

            self.accept_connections_event.set()

            try:
                self.host_socket.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass

            self.host_socket.close()
            self.host_thread.join()

            self.receiving_enabled = False
            self.receiving_allowed_indicator_signal.emit(False)
        except Exception as e:
            self.exception_signal.emit(f"An error occurred: {e}")

    # Opens ports on the network
    def open_ports(self) -> bool:
        try:
            # Opens the ports
            ok = self.wan_ip_service.addportmapping(
                self.host_port,         # external_port
                'TCP',                  # protocol
                self.host_internal_ip,  # internal_client
                self.host_port,         # internal_port
                'File Share',           # description
                '',                     # remote_host
                86400                   # lease_duration
            )

            if not ok:
                raise RuntimeError("UPnP port mapping failed")

            self.upnp_ports_open = True
            return True
        except Exception as e:
            if "ConflictInMappingEntry" in str(e) or 'refuse' in str(e).lower():
                self.exception_signal.emit(f"Error adding port mapping: Port may already be in use. Ports are not open")
            else:
                self.exception_signal.emit(f"Error adding port mapping: {e}. Ports are not open")

            return False

    # Closes the ports on the network
    def close_ports(self):
        try:
            # Deletes the port mapping
            ok = self.wan_ip_service.deleteportmapping(
                self.host_port,  # external_port
                'TCP',           # protocol
                ''               # remote_host
            )

            if not ok:
                raise RuntimeError("UPnP port unmapping failed")

            self.upnp_ports_open = False
        except Exception as e:
            self.exception_signal.emit(f"An error occurred: {e} | Ports are not closed")

    # Accept connections from clients
    def accept_connections(self):
        while not self.should_stop_receiving:
            try:
                if self.inbound_connection:
                    time.sleep(1)
                    continue

                self.accept_connections_event.clear()  # Clear the event since it may have been set

                self.host_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.host_socket.bind(("", self.host_port))
                self.host_socket.listen(1)

                client, address = self.host_socket.accept()

                self.host_socket_gateway = client
                self.inbound_peer_public_ip = address[0]

                # Exchange RSA keys
                serialized_sender_public_key = self.receive_intact_data(self.host_socket_gateway,
                                                                        self.serialized_public_key_size)
                self.sending_client_public_key = encryption.rsa_deserialize_public_key(serialized_sender_public_key)

                serialized_user_public_key = encryption.rsa_serialize_public_key(self.public_key)
                self.host_socket_gateway.send(serialized_user_public_key)

                # Receive AES information and decrypt it
                encrypted_aes_key = self.receive_intact_data(self.host_socket_gateway, self.common_message_size)
                self.host_socket_gateway.send(self.confirm_message)

                encrypted_aes_iv = self.receive_intact_data(self.host_socket_gateway, self.common_message_size)
                self.host_socket_gateway.send(self.confirm_message)

                signature = self.receive_intact_data(self.host_socket_gateway, self.common_message_size)
                self.host_socket_gateway.send(self.confirm_message)

                self.client_aes_key = encryption.rsa_decrypt(encrypted_aes_key, self.private_key)
                self.client_aes_iv = encryption.rsa_decrypt(encrypted_aes_iv, self.private_key)

                # Verify signature
                if not encryption.rsa_verify_signature(signature, self.client_aes_key, self.sending_client_public_key):
                    raise RuntimeError("Client AES key could not be verified")

                # Start the receive_metadata thread
                receive_metadata_thread = threading.Thread(target=self.receive_file_metadata)
                receive_metadata_thread.daemon = True
                receive_metadata_thread.start()

                self.host_socket.close()
                self.inbound_connection = True
                self.inbound_connection_indicator_signal.emit(True)

                self.accept_connections_event.wait()
            except ConnectionError:
                break
            except Exception as e:
                if self.should_stop_receiving:
                    break

                self.inbound_connection = False
                self.inbound_connection_indicator_signal.emit(False)
                self.exception_signal.emit(f"Error accepting connection: {e}")

    # Breaks the connection to the client
    def break_connection(self):
        if not self.outbound_connection:
            return

        try:
            if self.sending_files and not self.program_about_to_exit:
                raise RuntimeError("Cannot disconnect when currently sending files")
            if self.receiving_files and not self.program_about_to_exit:
                raise RuntimeError("Cannot disconnect when currently receiving files")

            # Close the client socket
            self.client_socket.close()
            self.outbound_connection = False
            self.outbound_connection_indicator_signal.emit(False)
        except Exception as e:
            self.exception_signal.emit(f"An error occurred: {e}")

    # Starts the request_connection thread
    def start_request_connection_thread(self, ip: str, port: int):
        if self.trying_to_connect:
            return

        self.trying_to_connect = True
        request_connection_thread = threading.Thread(target=self.request_connection, args=(ip, port))
        request_connection_thread.daemon = True
        request_connection_thread.start()

    # Sends a connection request to specified IP
    def request_connection(self, ip: str, port: int):
        try:
            if self.sending_files:
                raise RuntimeError("Cannot change connection when currently sending files")
            elif self.receiving_files:
                raise RuntimeError("Cannot change connection when currently receiving files")
            elif self.outbound_connection:
                raise RuntimeError("Cannot change connection when already connected")

            self.spinner_signal.emit(True)

            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((ip, port))

            # Exchange RSA keys
            serialized_user_public_key = encryption.rsa_serialize_public_key(self.public_key)
            self.client_socket.send(serialized_user_public_key)

            serialized_receiver_public_key = self.receive_intact_data(self.client_socket,
                                                                      self.serialized_public_key_size)
            self.receiving_client_public_key = encryption.rsa_deserialize_public_key(serialized_receiver_public_key)

            # Encrypt AES information and send it
            encrypted_aes_key = encryption.rsa_encrypt(self.host_aes_key, self.receiving_client_public_key)
            encrypted_aes_iv = encryption.rsa_encrypt(self.host_aes_iv, self.receiving_client_public_key)
            signature = encryption.rsa_sign(self.host_aes_key, self.private_key)

            self.client_socket.send(encrypted_aes_key)
            self.receive_intact_data(self.client_socket, self.confirmation_message_size)

            self.client_socket.send(encrypted_aes_iv)
            self.receive_intact_data(self.client_socket, self.confirmation_message_size)

            self.client_socket.send(signature)
            self.receive_intact_data(self.client_socket, self.confirmation_message_size)

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
            self.trying_to_connect = False
            self.spinner_signal.emit(False)

    # Gets the external IP of the host
    def get_host_external_ip(self) -> str:
        try:
            if self.upnp_enabled:
                ip = self.wan_ip_service.externalipaddress()
                return ip
            else:
                # Use a public API to get the external IP address
                response = requests.get("https://api64.ipify.org?format=json")
                ip = response.json()["ip"]
                return ip
        except Exception as e:
            self.exception_signal.emit(f"An error occurred: {e}")

    # Starts the thread for sending files
    def start_send_file_thread(self, file_path: str, file_name: str, file_size: int):
        if self.sending_files or not self.outbound_connection or file_path == "None":
            return

        self.sending_files = True
        self.reset_file_indicators_signal.emit()

        send_thread = threading.Thread(target=self.send_file, args=(file_path, file_name, file_size))
        send_thread.daemon = True
        send_thread.start()

    # Sends a file to the client
    def send_file(self, file_path: str, file_name: str, file_size: int):
        try:
            self.send_file_metadata(file_name, file_size)
            response = self.receive_intact_data(self.client_socket, self.confirmation_message_size).decode()

            if response == "Accepted":
                self.file_sent_indicator_signal.emit(False)
                self.send_file_data(file_path, file_name, file_size)
            elif response == "Rejected":
                self.sent_file_has_been_downloaded_signal.emit(False, file_name)
                self.file_sent_indicator_signal.emit(False)
            else:
                raise ConnectionError

            self.sending_files = False
        except ConnectionError:
            self.handle_connection_error(True)
        except Exception as e:
            self.exception_signal.emit(f"An error occurred: {e}")
            self.file_sent_indicator_signal.emit(False)

    # Sends the metadata of a file
    def send_file_metadata(self, file_name: str, file_size: int):
        try:
            metadata = {
                "file_name": file_name,
                "file_size": file_size,
            }
            metadata_json = json.dumps(metadata)

            encrypted_metadata = encryption.rsa_encrypt(metadata_json.encode(), self.receiving_client_public_key)
            signature = encryption.rsa_sign(metadata_json.encode(), self.private_key)

            # Send encrypted metadata and signature
            self.client_socket.send(encrypted_metadata)
            self.receive_intact_data(self.client_socket, self.confirmation_message_size)

            self.client_socket.send(signature)
            self.receive_intact_data(self.client_socket, self.confirmation_message_size)

            self.file_sent_indicator_signal.emit(True)
            self.receive_intact_data(self.client_socket, self.confirmation_message_size)
        except ConnectionError:
            self.handle_connection_error(True)
        except Exception as e:
            self.exception_signal.emit(f"An error occurred: {e}")
            self.file_sent_indicator_signal.emit(False)

    # Sends the data of a file
    def send_file_data(self, file_path: str, file_name: str, file_size: int):
        try:
            sent_data = 0

            with open(file_path, "rb") as file:
                while sent_data < file_size:
                    chunk = file.read(self.file_chunk_size)

                    sent_data += len(chunk)

                    # Add padding if last chunk
                    if len(chunk) < self.file_chunk_size:
                        chunk = encryption.aes_add_padding(chunk)

                    encrypted_chunk = encryption.aes_encrypt(chunk, self.host_aes_key, self.host_aes_iv)
                    self.client_socket.send(encrypted_chunk)

                    # Update the progress bar
                    progress_percentage = (sent_data / file_size) * 100
                    self.send_progress_bar_signal.emit(int(progress_percentage))

                    self.receive_intact_data(self.client_socket, self.confirmation_message_size)

            # Sync
            self.client_socket.send(self.confirm_message)
            self.receive_intact_data(self.client_socket, self.confirmation_message_size)

            self.sent_file_has_been_downloaded_signal.emit(True, file_name)
        except ConnectionError:
            self.handle_connection_error(True)
        except Exception as e:
            self.exception_signal.emit(f"An error occurred: {e}")

    # Rejects a file
    def reject_file(self):
        if not self.file_to_receive_exists or self.receiving_files:
            return

        try:
            self.host_socket_gateway.send("Rejected".encode())
            self.file_ready_to_receive_signal.emit(False)
            self.file_to_receive_exists = False
            self.metadata_event.set()  # Indicate that new metadata can be received
        except ConnectionError:
            self.handle_connection_error(False)
        except Exception as e:
            self.exception_signal.emit(f"An error occurred: {e}")

    # Starts the thread for receiving files
    def start_receive_file_thread(self):
        if self.receiving_files or not self.file_to_receive_exists:
            return

        try:
            self.receiving_files = True
            self.host_socket_gateway.send("Accepted".encode())
            receive_thread = threading.Thread(target=self.receive_file_data)
            receive_thread.daemon = True
            receive_thread.start()
        except ConnectionError:
            self.handle_connection_error(False)
        except Exception as e:
            self.exception_signal.emit(f"An error occurred: {e}")

    # Receives the metadata of a file
    def receive_file_metadata(self):
        while self.host_socket_gateway and not self.program_about_to_exit:
            try:
                self.metadata_event.clear()  # Clear the event since it may have been set

                # Receive encrypted metadata and signature
                encrypted_metadata = self.receive_intact_data(self.host_socket_gateway, self.common_message_size)
                self.host_socket_gateway.send(self.confirm_message)

                signature = self.receive_intact_data(self.host_socket_gateway, self.common_message_size)
                self.host_socket_gateway.send(self.confirm_message)

                if not encrypted_metadata or not signature:
                    raise ConnectionError

                metadata_json = encryption.rsa_decrypt(encrypted_metadata, self.private_key).decode()

                # Verify signature
                if encryption.rsa_verify_signature(signature, metadata_json.encode(), self.sending_client_public_key):
                    metadata = json.loads(metadata_json)

                    self.file_to_be_received_name = metadata["file_name"]
                    self.file_to_be_received_size = metadata["file_size"]
                    self.file_ready_to_receive_signal.emit(True)

                    self.host_socket_gateway.send(self.confirm_message)
                    self.file_to_receive_exists = True

                    self.metadata_event.wait()  # Block until there is new metadata to be received
                else:
                    raise RuntimeError("Metadata signature could not be verified")
            except ConnectionError:
                self.handle_connection_error(e, False)
                break
            except Exception as e:
                self.exception_signal.emit(f"An error occurred: {e}")
                break

    # Receives the data of a file
    def receive_file_data(self):
        try:
            file_path = os.path.join(os.path.expanduser("~"), "Downloads", self.file_to_be_received_name)  # Get the download folder
            received_data = 0

            with open(file_path, "wb") as file:
                while received_data < self.file_to_be_received_size:
                    # Make sure chunk is received intact
                    data_left = self.file_to_be_received_size - received_data

                    if self.file_chunk_size > data_left:
                        # Encrypted data is always a multiple of 16,
                        # and if already a multiple of 16, it gets 16 added to it
                        remainder = data_left % 16
                        length = (data_left - remainder) + 16

                        encrypted_chunk = self.receive_intact_data(self.host_socket_gateway, length)
                    else:
                        encrypted_chunk = self.receive_intact_data(self.host_socket_gateway, self.file_chunk_size)

                    chunk = encryption.aes_decrypt(encrypted_chunk, self.client_aes_key, self.client_aes_iv)

                    # Remove padding if last chunk
                    if received_data + len(chunk) > self.file_to_be_received_size:
                        chunk = encryption.aes_remove_padding(chunk)

                    file.write(chunk)
                    received_data += len(chunk)

                    # Update the progress bar
                    progress_percentage = (received_data / self.file_to_be_received_size) * 100
                    self.receive_progress_bar_signal.emit(int(progress_percentage))

                    self.host_socket_gateway.send(self.confirm_message)

            # Sync
            self.receive_intact_data(self.host_socket_gateway, self.confirmation_message_size)
            self.host_socket_gateway.send(self.confirm_message)

            self.file_ready_to_receive_signal.emit(False)
            self.file_to_receive_exists = False
            self.metadata_event.set()
        except ConnectionError:
                self.handle_connection_error(e, False)
        except Exception as e:
            self.exception_signal.emit(f"An error occurred: {e}")
        finally:
            self.receiving_files = False

    # Prepares the program for an exit
    def exit(self):
        self.program_about_to_exit = True
        self.disable_receiving()
        self.break_connection()

    def handle_connection_error(self, is_outbound: bool):
        self.exception_signal.emit("An existing connection was terminated.")

        if is_outbound:
            self.outbound_connection = False
            self.sending_files = False
            self.file_sent_indicator_signal.emit(False)
            self.outbound_connection_indicator_signal.emit(False)
        else:
            self.file_to_receive_exists = False
            self.receiving_files = False
            self.inbound_connection = False
            self.inbound_connection_indicator_signal.emit(False)
            self.file_ready_to_receive_signal.emit(False)
            self.accept_connections_event.set()
            self.metadata_event.set()
