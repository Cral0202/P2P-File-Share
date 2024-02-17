import json
import os
import socket
import threading
import requests
import logging
import upnpclient
from file_metadata import FileMetadata
from PyQt6.QtCore import QObject, pyqtSignal
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_pad
from cryptography.hazmat.primitives import padding as sym_pad
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class Network(QObject):
    receive_progress_bar_signal = pyqtSignal(float)  # The signal for the receive progress bar
    send_progress_bar_signal = pyqtSignal(float)  # The signal for the send progress bar
    connection_indicator_signal = pyqtSignal(bool)  # The signal for connection indicators
    file_sent_indicator_signal = pyqtSignal(bool)  # The signal for the file sent indicators
    receiving_allowed_indicator_signal = pyqtSignal(bool)  # The signal for enabled/disabled receiving indicators
    sent_file_has_been_downloaded_signal = pyqtSignal(str)  # The signal for if sent file has been downloaded
    file_ready_to_receive_signal = pyqtSignal(bool, str)  # The signal for files ready to be received
    reset_file_indicators_signal = pyqtSignal()  # The signal for resetting file indicators
    exception_signal = pyqtSignal(str)  # The signal for exceptions

    def __init__(self):
        super().__init__()

        self.private_key = None  # The host's private RSA key
        self.public_key = None  # The host's public RSA key
        self.receiving_client_public_key = None  # The public RSA key of a receiving user
        self.sending_client_public_key = None  # The public RSA key of a sending user
        self.generate_rsa_keys()  # Generate RSA keys

        self.host_aes_key = os.urandom(16)  # Generate a random secret key (16 bytes for AES-128)
        self.host_aes_iv = os.urandom(16)  # Generate a random initialization vector (IV) for CBC mode (16 bytes)
        self.host_cipher = Cipher(algorithms.AES(self.host_aes_key), modes.CBC(self.host_aes_iv))

        self.client_aes_key = None
        self.client_aes_iv = None
        self.client_cipher = None

        self.host_socket = None  # The socket that clients connect to
        self.host_socket_gateway = None  # The communication object for the host socket
        self.client_socket = None  # The socket used for connecting to other users
        self.host_thread = None  # Used for accepting connections

        self.wan_ip_service = None  # The WAN IP service object of the igd (for UPNP)
        self.upnp_enabled = self.is_upnp_enabled()  # True if UPNP is enabled on host network

        self.host_port = 12345  # Port which is opened and used
        self.host_internal_ip = socket.gethostbyname(socket.gethostname())  # The internal ip of the host
        self.host_external_ip = self.get_host_external_ip()  # The external ip of the host
        self.client_public_ip = None  # The public ip of the client

        self.receiving_enabled = False  # True if receiving is enabled
        self.should_stop_receiving = False  # True if receiving should be stopped
        self.connected = False  # True if connected to a client
        self.upnp_ports_open = False  # True if UPNP ports are open
        self.sending_files = False  # True if files are currently being sent
        self.receiving_files = False  # True if files are currently being received
        self.file_to_receive_exists = False  # True if there exists a file to receive
        self.trying_to_connect = False  # True if trying to connect to IP
        self.program_about_to_exit = False  # True if program is about to exit

        self.file_to_be_received_name = None  # The name of the file ready to be received
        self.file_to_be_received_size = None  # The size of the file ready to be received

        self.confirmation_message_size = 64  # The size to use for confirmation messages
        self.common_message_size = 1024  # The size to use for most messages, e.g. metadata or keys
        self.file_chunk_size = 65536  # The size to use for file chunks

        self.metadata_event = threading.Event()  # Used to sleep and wake metadata thread

    # Encrypt with AES
    def aes_encrypt(self, plaintext):
        encryptor = self.host_cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return ciphertext

    # Decrypt with AES
    def aes_decrypt(self, ciphertext):
        decryptor = self.client_cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext

    # Add padding to message
    def aes_add_padding(self, message):
        padder = sym_pad.PKCS7(128).padder()
        padded_message = padder.update(message) + padder.finalize()
        return padded_message

    # Remove padding from message
    def aes_remove_padding(self, message):
        unpadder = sym_pad.PKCS7(128).unpadder()
        unpadded_message = unpadder.update(message) + unpadder.finalize()
        return unpadded_message

    # Generate RSA keys
    def generate_rsa_keys(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

    # Encrypts a message with RSA
    def rsa_encrypt_message(self, message):
        ciphertext = self.receiving_client_public_key.encrypt(
            message,
            asym_pad.OAEP(
                mgf=asym_pad.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext

    # Decrypts a message with RSA
    def rsa_decrypt_message(self, ciphertext):
        plaintext = self.private_key.decrypt(
            ciphertext,
            asym_pad.OAEP(
                mgf=asym_pad.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext

    # Signs a message with RSA
    def rsa_sign_message(self, message):
        signature = self.private_key.sign(
            message,
            asym_pad.PSS(
                mgf=asym_pad.MGF1(hashes.SHA256()),
                salt_length=asym_pad.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    # Verifies a message's signature with RSA
    def rsa_verify_signature(self, signature, message):
        try:
            self.sending_client_public_key.verify(
                signature,
                message,
                asym_pad.PSS(
                    mgf=asym_pad.MGF1(hashes.SHA256()),
                    salt_length=asym_pad.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            logging.debug("Invalid signature")
            return False

    # Serialize a public key object into bytes
    def rsa_serialize_public_key(self, key):
        serialized_public_key = key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return serialized_public_key

    # Deserialize the bytes into a public key object
    def rsa_deserialize_public_key(self, key):
        public_key = serialization.load_pem_public_key(
            key,
            backend=default_backend()
        )
        return public_key

    # Checks if UPNP is enabled on network, and if so sets it up for use
    def is_upnp_enabled(self):
        try:
            self.wan_ip_service = self.get_wan_ip_service()
            return True
        except Exception:
            return False

    # Gets the service to use for WAN IP connections
    def get_wan_ip_service(self):
        devices = upnpclient.discover()

        # Get the IGD
        igd = None
        for device in devices:
            if "InternetGatewayDevice" in device.device_type:
                igd = device
                break
            else:
                pass

        # Get the correct service
        services = igd.services
        for service in services:
            for action in service.actions:
                if action.name == "AddPortMapping":
                    return service
                else:
                    pass

    # Enables receiving
    def enable_receiving(self):
        if not self.receiving_enabled:
            try:
                if self.upnp_enabled and not self.upnp_ports_open:
                    if not self.open_ports():
                        return

                self.should_stop_receiving = False

                self.host_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.host_socket.bind(("", self.host_port))
                self.host_socket.listen(1)

                self.host_thread = threading.Thread(target=self.accept_connections)
                self.host_thread.daemon = True
                self.host_thread.start()

                self.receiving_enabled = True
                self.receiving_allowed_indicator_signal.emit(True)
            except Exception as e:
                self.exception_signal.emit(f"An error occurred: {e}")
                logging.debug(f"An error occurred: {e}")

    # Disables receiving
    def disable_receiving(self):
        if self.receiving_enabled:
            try:
                if self.sending_files and not self.program_about_to_exit:
                    raise RuntimeError("Cannot disable receiving when currently sending files")
                if self.receiving_files and not self.program_about_to_exit:
                    raise RuntimeError("Cannot disable receiving when currently receiving files")

                if self.upnp_ports_open:
                    self.close_ports()

                self.should_stop_receiving = True

                self.host_socket.close()
                self.host_thread.join()

                self.receiving_enabled = False
                self.receiving_allowed_indicator_signal.emit(False)
            except Exception as e:
                self.exception_signal.emit(f"An error occurred: {e}")
                logging.debug(f"An error occurred: {e}")

    # Opens ports on the network
    def open_ports(self):
        try:
            # Opens the ports
            self.wan_ip_service.AddPortMapping(
                NewRemoteHost="",
                NewExternalPort=self.host_port,
                NewProtocol="TCP",
                NewInternalPort=self.host_port,
                NewInternalClient=self.host_internal_ip,
                NewEnabled="1",
                NewPortMappingDescription="File Share",
                NewLeaseDuration=86400
            )
            self.upnp_ports_open = True
            return True
        except Exception as e:
            if "ConflictInMappingEntry" in str(e):
                self.exception_signal.emit(f"Error adding port mapping: Port may already be in use. Ports are not open")
            else:
                self.exception_signal.emit(f"Error adding port mapping: {e}. Ports are not open")
            logging.debug(f"An error occurred: {e}")
            return False

    # Closes the ports on the network
    def close_ports(self):
        try:
            # Deletes the port mapping
            self.wan_ip_service.DeletePortMapping(
                NewRemoteHost="",
                NewExternalPort=self.host_port,
                NewProtocol="TCP"
            )
            self.upnp_ports_open = False
        except Exception as e:
            self.exception_signal.emit(f"An error occurred: {e} | Ports are not closed")
            logging.debug(f"An error occurred: {e}")

    # Accept connections from clients
    def accept_connections(self):
        while not self.should_stop_receiving:
            try:
                client, address = self.host_socket.accept()
                self.host_socket_gateway = client

                # Exchange RSA keys
                serialized_sender_public_key = self.host_socket_gateway.recv(self.common_message_size)
                self.sending_client_public_key = self.rsa_deserialize_public_key(serialized_sender_public_key)

                serialized_user_public_key = self.rsa_serialize_public_key(self.public_key)
                self.host_socket_gateway.send(serialized_user_public_key)

                # Receive AES information and decrypt it
                encrypted_aes_key = self.host_socket_gateway.recv(self.common_message_size)
                self.host_socket_gateway.send("received".encode())

                encrypted_aes_iv = self.host_socket_gateway.recv(self.common_message_size)
                self.host_socket_gateway.send("received".encode())

                signature = self.host_socket_gateway.recv(self.common_message_size)
                self.host_socket_gateway.send("received".encode())

                self.client_aes_key = self.rsa_decrypt_message(encrypted_aes_key)
                self.client_aes_iv = self.rsa_decrypt_message(encrypted_aes_iv)

                # Verify signature
                if self.rsa_verify_signature(signature, self.client_aes_key):
                    self.client_cipher = Cipher(algorithms.AES(self.client_aes_key), modes.CBC(self.client_aes_iv))
                else:
                    raise RuntimeError("Client AES key could not be verified")

                # Start the receive_metadata thread
                receive_metadata_thread = threading.Thread(target=self.receive_file_metadata)
                receive_metadata_thread.daemon = True
                receive_metadata_thread.start()
            except Exception as e:
                if self.should_stop_receiving:
                    break
                self.exception_signal.emit(f"Error accepting connection: {e}")
                logging.debug(f"An error occurred: {e}")

    # Breaks the connection to the client
    def break_connection(self):
        if self.connected:
            try:
                if self.sending_files and not self.program_about_to_exit:
                    raise RuntimeError("Cannot disconnect when currently sending files")
                if self.receiving_files and not self.program_about_to_exit:
                    raise RuntimeError("Cannot disconnect when currently receiving files")

                # Close the client socket
                self.client_socket.close()
                self.connected = False
                self.connection_indicator_signal.emit(False)
            except Exception as e:
                self.exception_signal.emit(f"An error occurred: {e}")
                logging.debug(f"An error occurred: {e}")

    # Starts the request_connection thread
    def start_request_connection_thread(self, ip, port):
        if not self.trying_to_connect:
            self.trying_to_connect = True
            request_connection_thread = threading.Thread(target=self.request_connection, args=(ip, port))
            request_connection_thread.daemon = True
            request_connection_thread.start()

    # Sends a connection request to specified IP
    def request_connection(self, ip, port):
        try:
            if self.sending_files:
                raise RuntimeError("Cannot change connection when currently sending files")
            if self.receiving_files:
                raise RuntimeError("Cannot change connection when currently receiving files")

            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((ip, port))

            # Exchange RSA keys
            serialized_user_public_key = self.rsa_serialize_public_key(self.public_key)
            self.client_socket.send(serialized_user_public_key)

            serialized_receiver_public_key = self.client_socket.recv(self.common_message_size)
            self.receiving_client_public_key = self.rsa_deserialize_public_key(serialized_receiver_public_key)

            # Encrypt AES information and send it
            encrypted_aes_key = self.rsa_encrypt_message(self.host_aes_key)
            encrypted_aes_iv = self.rsa_encrypt_message(self.host_aes_iv)
            signature = self.rsa_sign_message(self.host_aes_key)

            self.client_socket.send(encrypted_aes_key)
            self.client_socket.recv(self.confirmation_message_size)

            self.client_socket.send(encrypted_aes_iv)
            self.client_socket.recv(self.confirmation_message_size)

            self.client_socket.send(signature)
            self.client_socket.recv(self.confirmation_message_size)

            self.client_public_ip = ip
            self.connected = True
            self.trying_to_connect = False
            self.connection_indicator_signal.emit(True)
        except ConnectionRefusedError:
            self.exception_signal.emit(f"Connection to {ip} refused.")
            self.connection_indicator_signal.emit(False)
            self.trying_to_connect = False
            logging.debug(f"An error occurred: Connection to {ip} refused.")
        except Exception as e:
            self.exception_signal.emit(f"An error occurred: {e}")
            self.connection_indicator_signal.emit(False)
            self.trying_to_connect = False
            logging.debug(f"An error occurred: {e}")

    # Gets the external IP of the host
    def get_host_external_ip(self):
        if self.upnp_enabled:
            try:
                ip_unformatted = self.wan_ip_service.GetExternalIPAddress()
                ip = ip_unformatted["NewExternalIPAddress"]  # Get the IP-address part
                return ip
            except Exception as e:
                self.exception_signal.emit(f"An error occurred: {e}")
                logging.debug(f"An error occurred: {e}")
        else:
            try:
                # Use a public API to get the external IP address
                response = requests.get("https://api64.ipify.org?format=json")
                ip = response.json()["ip"]
                return ip
            except requests.RequestException as e:
                self.exception_signal.emit(f"An error occurred: {e}")
                logging.debug(f"An error occurred: {e}")

    # Starts the thread for sending files
    def start_send_file_thread(self, file_path, file_name, file_size):
        if not self.sending_files and self.connected and file_path != "None":
            self.sending_files = True
            self.reset_file_indicators_signal.emit()

            send_thread = threading.Thread(target=self.send_file, args=(file_path, file_name, file_size))
            send_thread.daemon = True
            send_thread.start()

    # Sends a file to the client
    def send_file(self, file_path, file_name, file_size):
        self.send_file_metadata(file_name, file_size)
        self.send_file_data(file_path, file_name, file_size)
        self.sending_files = False

    # Sends the metadata of a file
    def send_file_metadata(self, file_name, file_size):
        try:
            metadata = FileMetadata(None, file_name, file_size)
            metadata_json = json.dumps(metadata.__dict__)  # Serialize metadata to JSON

            encrypted_metadata = self.rsa_encrypt_message(metadata_json.encode())
            signature = self.rsa_sign_message(metadata_json.encode())

            # Send encrypted metadata and signature
            self.client_socket.send(encrypted_metadata)
            self.client_socket.recv(self.confirmation_message_size)

            self.client_socket.send(signature)
            self.client_socket.recv(self.confirmation_message_size)

            self.file_sent_indicator_signal.emit(True)
            self.client_socket.recv(self.confirmation_message_size)
        except Exception as e:
            self.exception_signal.emit(f"An error occurred: {e}")
            self.file_sent_indicator_signal.emit(False)
            logging.debug(f"An error occurred: {e}")

    # Sends the data of a file
    def send_file_data(self, file_path, file_name, file_size):
        try:
            sent_data = 0
            with open(file_path, "rb") as file:
                while True:
                    chunk = file.read(self.file_chunk_size)

                    sent_data += len(chunk)

                    # Add padding if last chunk
                    if len(chunk) < self.file_chunk_size:
                        chunk = self.aes_add_padding(chunk)

                    encrypted_chunk = self.aes_encrypt(chunk)
                    self.client_socket.send(encrypted_chunk)

                    # Update the progress bar
                    progress_percentage = (sent_data / file_size) * 100
                    self.send_progress_bar_signal.emit(progress_percentage)

                    self.client_socket.recv(self.confirmation_message_size)

                    if sent_data >= file_size:
                        self.client_socket.send("Sync".encode())
                        break

            self.client_socket.recv(self.confirmation_message_size)
            self.sent_file_has_been_downloaded_signal.emit(file_name)
        except Exception as e:
            self.exception_signal.emit(f"An error occurred: {e}")
            logging.debug(f"An error occurred: {e}")

    # Starts the thread for sending files
    def start_receive_file_thread(self):
        if not self.receiving_files and self.file_to_receive_exists:
            self.receiving_files = True
            receive_thread = threading.Thread(target=self.receive_file)
            receive_thread.daemon = True
            receive_thread.start()

    # Receives a file
    def receive_file(self):
        self.receive_file_data(self.file_to_be_received_name, self.file_to_be_received_size)
        self.receiving_files = False

    # Receives the metadata of a file
    def receive_file_metadata(self):
        while self.host_socket_gateway and not self.program_about_to_exit:
            try:
                self.metadata_event.clear()  # Clear the event since it may have been set

                # Receive encrypted metadata and signature
                encrypted_metadata = self.host_socket_gateway.recv(self.common_message_size)
                self.host_socket_gateway.send("received".encode())

                signature = self.host_socket_gateway.recv(self.common_message_size)
                self.host_socket_gateway.send("received".encode())

                if not encrypted_metadata or not signature:
                    raise ConnectionError

                metadata_json = self.rsa_decrypt_message(encrypted_metadata).decode()

                # Verify signature
                if self.rsa_verify_signature(signature, metadata_json.encode()):
                    metadata_dict = json.loads(metadata_json)  # Convert JSON string to dictionary
                    metadata = FileMetadata(**metadata_dict)  # Unpack metadata_dict and create an object from it

                    self.file_ready_to_receive_signal.emit(True, metadata.file_name)
                    self.file_to_be_received_name = metadata.file_name
                    self.file_to_be_received_size = metadata.file_size

                    self.host_socket_gateway.send("Metadata received".encode())
                    self.file_to_receive_exists = True

                    self.metadata_event.wait()  # Block until there is new metadata to be received
                else:
                    raise RuntimeError("Metadata signature could not be verified")
            except ConnectionError:
                # ConnectionError occurs when the socket is closed
                break
            except json.JSONDecodeError:
                # JSONDecodeError occurs when the received data is not valid JSON
                break
            except Exception as e:
                self.exception_signal.emit(f"An error occurred: {e}")
                logging.debug(f"An error occurred: {e}")
                break

    # Receives the data of a file
    def receive_file_data(self, file_name, file_size):
        try:
            file_path = os.path.join(os.path.expanduser("~"), "Downloads", file_name)  # Get the download folder
            received_data = 0
            with open(file_path, "wb") as file:
                while received_data < file_size:
                    encrypted_chunk = self.host_socket_gateway.recv(self.file_chunk_size)
                    chunk = self.aes_decrypt(encrypted_chunk)

                    # Remove padding if last chunk
                    if received_data + len(chunk) > file_size:
                        chunk = self.aes_remove_padding(chunk)

                    file.write(chunk)
                    received_data += len(chunk)

                    # Update the progress bar
                    progress_percentage = (received_data / file_size) * 100
                    self.receive_progress_bar_signal.emit(progress_percentage)

                    self.host_socket_gateway.send("Chunk received".encode())

                    if received_data >= file_size:
                        self.host_socket_gateway.recv(self.confirmation_message_size)
                        break

            self.file_ready_to_receive_signal.emit(True, None)  # Reset label
            self.host_socket_gateway.send("File downloaded".encode())
            self.file_to_receive_exists = False  # Indicate that there is no new file to receive
            self.metadata_event.set()  # Indicate that new metadata can be received
        except Exception as e:
            self.exception_signal.emit(f"An error occurred: {e}")
            logging.debug(f"An error occurred: {e}")

    # Prepares the program for an exit
    def exit(self):
        self.program_about_to_exit = True
        self.disable_receiving()
        self.break_connection()
