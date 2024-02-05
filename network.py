import socket
import threading
import upnpy
import re


class Network:
    def __init__(self):
        self.host_socket = None
        self.client_socket = None
        self.host_thread = None

        self.upnp = upnpy.UPnP()
        self.wan_ip_service = self.get_wan_ip_service()  # The wan ip service object of the igd

        self.host_port = 12345  # Port which is opened and used
        self.client_port = 23456
        self.host_internal_ip = socket.gethostbyname(socket.gethostname())  # The internal ip of host
        self.host_public_ip = self.get_host_public_ip()  # The public ip of host
        self.client_public_ip = None  # The public ip of the client

        self.networking_enabled = False  # True if networking is enabled
        self.should_stop_threads = False  # True if threads should be stopped
        self.connected = False  # True if connected to a client

        self.exceptionMessage = None

    # Gets the service to use for WAN IP connections
    def get_wan_ip_service(self):
        try:
            self.upnp.discover()  # Discover UPnP devices on the network, returns a list of devices
            igd = self.upnp.get_igd()  # Select the IGD

            # Gets the services of the igd and selects the correct one
            for option in igd.get_services():
                if re.search(r"(?i)(?=.*WAN.*)(?=.*Conn.*)", option.id):  # True if any instance of wan and conn
                                                                          # exists in the string, no matter the pattern
                    service = igd[option.id.split(':')[-1]]  # Extract the ID part of the string
                    return service

            self.exceptionMessage = "No compatible IGD service found for WANIPConnection."
        except Exception as e:
            self.exceptionMessage = f"An error occurred: {e}"

    # Enables networking
    def enable_networking(self):
        if not self.networking_enabled:
            try:
                self.should_stop_threads = False
                self.open_ports()

                self.host_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.host_socket.bind(('0.0.0.0', self.host_port))
                self.host_socket.listen(1)

                self.host_thread = threading.Thread(target=self.accept_connections)
                self.host_thread.start()
                self.networking_enabled = True
            except Exception as e:
                self.exceptionMessage = f"An error occurred: {e}"

    # Disables networking
    def disable_networking(self):
        if self.networking_enabled:
            try:
                self.should_stop_threads = True
                self.host_socket.close()
                self.host_thread.join()
                self.close_ports()

                self.networking_enabled = False
            except Exception as e:
                self.exceptionMessage = f"An error occurred: {e}"

    # Opens ports on the network
    def open_ports(self):
        # Opens the ports
        try:
            for option in self.wan_ip_service.get_actions():
                if re.search(r"(?i)(?=.*add.*)(?=.*port.*)", option.name):  # True if any instance of add and
                                                                          # port exists in the string, no matter
                                                                          # the pattern
                    add_port_map = getattr(self.wan_ip_service, option.name)  # Combine the function name
                                                                              # into a function
                    add_port_map(
                        NewRemoteHost="",
                        NewExternalPort=self.host_port,
                        NewProtocol="TCP",
                        NewInternalPort=self.host_port,
                        NewInternalClient=self.host_internal_ip,
                        NewEnabled=1,
                        NewPortMappingDescription="File Share",
                        NewLeaseDuration=0
                    )
                    return

            self.exceptionMessage = "No compatible IGD service found for AddPortMapping."
        except Exception as e:
            self.exceptionMessage = f"Error adding port mapping: {e}"

    # Closes the ports on the network
    def close_ports(self):
        try:
            # Deletes the port mapping
            self.wan_ip_service.DeletePortMapping(
                NewRemoteHost="",
                NewExternalPort=self.host_port,
                NewProtocol="TCP"
            )
        except Exception as e:
            self.exceptionMessage = f"An error occurred: {e}"

    # Accept connections from clients
    def accept_connections(self):
        self.host_socket.settimeout(1.0)  # Set the timeout for the socket to make it non-blocking
        while not self.should_stop_threads:
            try:
                client, address = self.host_socket.accept()
            except socket.timeout:
                # Check if the threads should be stopped
                if self.should_stop_threads:
                    break
            except Exception as e:
                if self.should_stop_threads:
                    break
                self.exceptionMessage = f"Error accepting connection: {e}"

    # Breaks the connection to the client
    def break_connection(self):
        if self.connected:
            try:
                # Close the client socket
                self.client_socket.close()
                self.connected = False
            except Exception as e:
                self.exceptionMessage = f"An error occurred: {e}"

    # Sends a connection request to specified IP
    def request_connection(self, ip):
        if not self.connected:
            if not ip:
                self.exceptionMessage = "IP-address is empty."
                return

            try:
                self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.client_socket.connect((ip, self.host_port))  # Connect to the specified IP and port
                self.client_public_ip = ip
                self.connected = True
            except ConnectionRefusedError:
                self.exceptionMessage = f"Connection to {ip} refused."
            except Exception as e:
                self.exceptionMessage = f"An error occurred: {e}"

    # Gets the public IP of the host
    def get_host_public_ip(self):
        try:
            for option in self.wan_ip_service.get_actions():
                if re.search(r"(?i)(?=.*IP.*)(?=.*ext.*)", option.name):  # True if any instance of IP and
                                                                          # ext exists in the string, no matter
                                                                          # the pattern
                    ip_function = getattr(self.wan_ip_service, option.name)  # Combine the function name into a function
                    ip = ip_function()
                    ip_formatted = ip["NewExternalIPAddress"]  # Get the IP-address part
                    return ip_formatted

            self.exceptionMessage = "No compatible IGD service found for GetExternalIPAddress."
        except Exception as e:
            self.exceptionMessage = f"An error occurred: {e}"

    # Prepares the program for an exit
    def exit(self):
        self.disable_networking()
