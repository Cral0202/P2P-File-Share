import json
import os
import socket
import threading
import time

import requests
import upnpy
from file_metadata import FileMetadata
from PyQt6.QtCore import QObject, pyqtSignal


class Network(QObject):
    receive_progress_bar_signal = pyqtSignal(float)  # The signal for the receive progress bar
    send_progress_bar_signal = pyqtSignal(float)  # The signal for the send progress bar
    connection_indicator_signal = pyqtSignal(bool)  # The signal for connection indicators
    file_sent_indicator_signal = pyqtSignal(bool)  # The signal for the file sent indicators
    receiving_allowed_indicator_signal = pyqtSignal(bool)  # The signal for enabled/disabled receiving indicators
    sent_file_has_been_downloaded_signal = pyqtSignal(str)  # The signal for if sent file has been downloaded
    file_ready_to_receive_signal = pyqtSignal(str)  # The signal for files ready to be received
    exception_signal = pyqtSignal(str)  # The signal for exceptions

    def __init__(self):
        super().__init__()

        self.host_socket = None  # The socket that clients connect to
        self.host_socket_gateway = None  # Used for communication when receiving files
        self.client_socket = None  # Used for communication when sending files
        self.host_thread = None  # Used for accepting connections

        self.upnp = upnpy.UPnP()
        self.wan_ip_service = None  # The WAN IP service object of the igd (for UPNP)
        self.upnp_enabled = self.is_upnp_enabled()  # True if UPNP is enabled on host network

        self.host_port = 12345  # Port which is opened and used
        self.host_internal_ip = socket.gethostbyname(socket.gethostname())  # The internal ip of host
        self.host_external_ip = self.get_host_external_ip()  # The external ip of host
        self.client_public_ip = None  # The public ip of the client

        self.receiving_enabled = False  # True if receiving is enabled
        self.should_stop_threads = False  # True if threads should be stopped
        self.connected = False  # True if connected to a client
        self.upnp_ports_open = False  # True if UPNP ports are open
        self.sending_files = False  # True if files are currently being sent
        self.receiving_files = False  # True if files are currently being received

        self.file_to_be_received_name = None  # The name of the file ready to be received
        self.file_to_be_received_size = None  # The size of the file ready to be received

        self.metadata_event = threading.Event()  # Used to sleep and wake metadata thread

    # Checks if UPNP is enabled on network, and if so sets it up for use
    def is_upnp_enabled(self):
        try:
            self.wan_ip_service = self.get_wan_ip_service()
            return True
        except Exception as e:
            return False

    # Gets the service to use for WAN IP connections
    def get_wan_ip_service(self):
        self.upnp.discover()  # Discover UPnP devices on the network, returns a list of devices
        igd = self.upnp.get_igd()  # Select the IGD

        # Check for services supporting port forwarding
        for service in igd.get_services():
            if self.supports_port_forwarding(service):
                service = igd[service.id.split(':')[-1]]  # Extract the ID part of the string
                return service

    # Checks if the service supports port forwarding by examining its actions
    def supports_port_forwarding(self, service):
        for action in service.get_actions():
            if action.name == "AddPortMapping":
                return True
        return False

    # Enables receiving
    def enable_receiving(self):
        if not self.receiving_enabled:
            try:
                if self.upnp_enabled and not self.upnp_ports_open:
                    self.open_ports()

                self.should_stop_threads = False

                self.host_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.host_socket.bind(("", self.host_port))
                self.host_socket.listen(1)

                self.host_thread = threading.Thread(target=self.accept_connections)
                self.host_thread.start()

                self.receiving_enabled = True
                self.receiving_allowed_indicator_signal.emit(True)
            except Exception as e:
                self.exception_signal.emit(f"An error occurred: {e}")

    # Disables receiving
    def disable_receiving(self):
        if self.receiving_enabled:
            try:
                if self.upnp_ports_open:
                    self.close_ports()

                self.should_stop_threads = True

                self.host_socket.close()
                self.host_thread.join()

                self.receiving_enabled = False
                self.receiving_allowed_indicator_signal.emit(False)
            except Exception as e:
                self.exception_signal.emit(f"An error occurred: {e}")

    # Opens ports on the network
    def open_ports(self):
        # Opens the ports
        try:
            self.wan_ip_service.AddPortMapping(
                NewRemoteHost="",
                NewExternalPort=self.host_port,
                NewProtocol="TCP",
                NewInternalPort=self.host_port,
                NewInternalClient=self.host_internal_ip,
                NewEnabled=1,
                NewPortMappingDescription="File Share",
                NewLeaseDuration=0
            )
            self.upnp_ports_open = True
        except Exception as e:
            self.exception_signal.emit(f"Error adding port mapping: {e} | Ports are not open")

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

    # Accept connections from clients
    def accept_connections(self):
        self.host_socket.settimeout(1.0)  # Set the timeout for the socket to make it non-blocking
        while not self.should_stop_threads:
            try:
                client, address = self.host_socket.accept()
                self.host_socket_gateway = client

                # Start the receive metadata thread
                receive_metadata_thread = threading.Thread(target=self.receive_file_metadata)
                receive_metadata_thread.daemon = True
                receive_metadata_thread.start()
            except socket.timeout:
                # Check if the threads should be stopped
                if self.should_stop_threads:
                    break
            except Exception as e:
                if self.should_stop_threads:
                    break
                self.exception_signal.emit(f"Error accepting connection: {e}")

    # Breaks the connection to the client
    def break_connection(self):
        if self.connected:
            try:
                # Close the client socket
                self.client_socket.close()
                self.connected = False
                self.connection_indicator_signal.emit(False)
            except Exception as e:
                self.exception_signal.emit(f"An error occurred: {e}")

    # Sends a connection request to specified IP
    def request_connection(self, ip):
        if not self.connected:
            if not ip:
                self.exception_signal.emit("IP-address is empty.")
                return

            try:
                self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.client_socket.connect((ip, self.host_port))  # Connect to the specified IP and port

                self.client_public_ip = ip
                self.connected = True
                self.connection_indicator_signal.emit(True)
            except ConnectionRefusedError:
                self.exception_signal.emit(f"Connection to {ip} refused.")
                self.connection_indicator_signal.emit(False)
            except Exception as e:
                self.exception_signal.emit(f"An error occurred: {e}")
                self.connection_indicator_signal.emit(False)

    # Gets the external IP of the host
    def get_host_external_ip(self):
        if self.upnp_enabled:
            try:
                ip_unformatted = self.wan_ip_service.GetExternalIPAddress()
                ip = ip_unformatted["NewExternalIPAddress"]  # Get the IP-address part
                return ip
            except Exception as e:
                self.exception_signal.emit(f"An error occurred: {e}")
        else:
            try:
                # Use a public API to get the external IP address
                response = requests.get("https://api64.ipify.org?format=json")
                ip = response.json()["ip"]
                return ip
            except requests.RequestException as e:
                self.exception_signal.emit(f"An error occurred: {e}")

    # Starts the thread for sending files
    def start_send_file_thread(self, file_name, file_size, file_path):
        if not self.sending_files:
            self.sending_files = True
            send_thread = threading.Thread(target=self.send_file, args=(file_name, file_size, file_path))
            send_thread.daemon = True
            send_thread.start()

    # Sends a file to the client
    def send_file(self, file_name, file_size, file_path):
        self.send_file_metadata(file_name, file_size)
        self.send_file_data(file_path, file_size)
        self.sending_files = False

    # Sends the metadata of a file
    def send_file_metadata(self, file_name, file_size):
        try:
            metadata = FileMetadata(file_name, file_size)
            metadata_json = json.dumps(metadata.__dict__)  # Serialize metadata to JSON
            self.client_socket.send(metadata_json.encode())  # Encode and send JSON data
            self.file_sent_indicator_signal.emit(True)  # Signal that the file has been sent
            self.client_socket.recv(1024)  # Wait for confirmation that metadata has been received
        except Exception as e:
            self.exception_signal.emit(f"An error occurred: {e}")
            self.file_sent_indicator_signal.emit(False)  # Signal that the file has not been sent

    # Sends the data of a file
    def send_file_data(self, file_path, file_size):
        try:
            chunk_size = 1024
            sent_data = 0
            with open(file_path, "rb") as file:
                # Keep sending chunks until end of file
                while True:
                    chunk = file.read(chunk_size)
                    if not chunk:
                        break  # End of file
                    self.client_socket.send(chunk)  # Send the chunk
                    sent_data += len(chunk)

                    # Update the progress bar
                    progress_percentage = (sent_data / file_size) * 100
                    self.send_progress_bar_signal.emit(progress_percentage)

            downloaded_file_name = self.client_socket.recv(
                1024).decode()  # Wait for confirmation that the sent file has been downloaded
            self.sent_file_has_been_downloaded_signal.emit(downloaded_file_name)  # Signal that file has been downloaded
        except Exception as e:
            self.exception_signal.emit(f"An error occurred: {e}")

    # Starts the thread for sending files
    def start_receive_file_thread(self):
        if not self.receiving_files:
            self.receiving_files = True
            receive_thread = threading.Thread(target=self.receive_file)
            receive_thread.daemon = True
            receive_thread.start()

    # Receives a file
    def receive_file(self):
        # name, size = self.receive_file_metadata()
        self.receive_file_data(self.file_to_be_received_name, self.file_to_be_received_size)
        self.receiving_files = False

    # Receives the metadata of a file
    def receive_file_metadata(self):
        while self.host_socket_gateway:
            try:
                self.metadata_event.clear()  # Clear the event since it may have been set

                metadata_json = self.host_socket_gateway.recv(1024).decode()  # Receive and decode metadata
                metadata_dict = json.loads(metadata_json)  # Convert JSON string to dictionary
                metadata = FileMetadata(**metadata_dict)  # Unpack metadata_dict and create an object from it

                self.file_ready_to_receive_signal.emit(metadata.file_name)
                self.file_to_be_received_name = metadata.file_name
                self.file_to_be_received_size = metadata.file_size

                self.host_socket_gateway.send("Metadata received".encode())  # Send confirmation that metadata has been
                                                                             # received

                self.metadata_event.wait()  # Block until there is new metadata to be received
            except ConnectionError:
                # ConnectionError occurs when the socket is closed
                break
            except json.JSONDecodeError:
                # JSONDecodeError occurs when the received data is not valid JSON
                break
            except Exception as e:
                self.exception_signal.emit(f"An error occurred: {e}")
                break

    # Receives the data of a file
    def receive_file_data(self, file_name, file_size):
        try:
            file_path = os.path.join(os.path.expanduser("~"), "Downloads", file_name)  # Get the download folder
            chunk_size = 1024
            received_data = 0
            with open(file_path, "wb") as file:
                while received_data < file_size:
                    chunk = self.host_socket_gateway.recv(min(chunk_size, file_size - received_data))
                    if not chunk:
                        break  # No more data to get
                    file.write(chunk)
                    received_data += len(chunk)

                    # Update the progress bar
                    progress_percentage = (received_data / file_size) * 100
                    self.receive_progress_bar_signal.emit(progress_percentage)

            self.host_socket_gateway.send(file_name.encode())  # Send confirmation that file has been downloaded
            self.metadata_event.set()  # Indicate that new metadata can be received
        except Exception as e:
            self.exception_signal.emit(f"An error occurred: {e}")

    # Prepares the program for an exit
    def exit(self):
        self.disable_receiving()
