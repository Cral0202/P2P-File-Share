import ipaddress

from PyQt6.QtCore import QObject, pyqtSignal
from network import Network, NetworkEvent
from contact_storage import ContactStorage
from models.host_info import HostInfo

class SessionController(QObject):
    outbound_status_signal = pyqtSignal(str, bool)
    inbound_status_signal = pyqtSignal(str, bool)
    receiving_status_signal = pyqtSignal(str, bool)
    receive_pgrs_bar_signal = pyqtSignal(int)
    send_pgrs_bar_signal = pyqtSignal(int)
    download_signal = pyqtSignal(str)
    file_indicators_signal = pyqtSignal()
    connecting_spinner_signal = pyqtSignal(bool)
    file_sent_signal = pyqtSignal(bool)
    receive_label_signal = pyqtSignal(str, bool)
    info_signal = pyqtSignal(str, int)
    selected_file_signal = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self._network = Network()
        self._contact_storage = ContactStorage()

    def initialize(self):
        self._network.subscribe(self._on_network_event)
        self._network.initialize()

    def _on_outbound_change(self, connected: bool):
        if connected:
            text = f"Outbound connection to: {self._network.outbound_peer_public_ip}"
        else:
            text = "No outbound connection"

        self.outbound_status_signal.emit(text, connected)

    def _on_inbound_change(self, connected: bool):
        if connected:
            text = f"Inbound connection from: {self._network.inbound_peer_public_ip}"
        else:
            text = "No inbound connection"

        self.inbound_status_signal.emit(text, connected)

    def _on_receiving_change(self, enabled: bool):
        if enabled:
            text = "Receiving enabled"
        else:
            text = "Receiving disabled"

        self.receiving_status_signal.emit(text, enabled)

    def _on_downloaded_change(self, downloaded: bool, file_name: str):
        if downloaded:
            text = f"The sent file \"{file_name}\" has been downloaded by the receiver."
        else:
            text = f"The sent file \"{file_name}\" was rejected by the receiver."

        self.download_signal.emit(text)

    def _update_receive_label(self, reset_pgrs_bar: bool):
        if reset_pgrs_bar:
            text = f"Ready to receive: {self._network.incoming_file.name}"
        else:
            text = "Ready to receive:"

        self.receive_label_signal.emit(text, reset_pgrs_bar)

    ############
    # Requests #
    ############

    def request_set_port(self, port: int):
        self._network.host_port = port

    def request_disconnect(self):
        try:
            self._network.break_connection()
            self._on_outbound_change(False)
        except Exception as e:
            self.info_signal.emit(str(e), 10000)

    def request_enable_receiving(self):
        try:
            self._network.enable_receiving()
            self._on_receiving_change(True)
        except Exception as e:
            text = str(e)

            if "ConflictInMappingEntry" in text or "refuse" in text.lower():
                text = "UPnP port mapping failed. Port may already be in use."

            self.info_signal.emit(text, 10000)

    def request_disable_receiving(self):
        try:
            self._network.disable_receiving()
            self._on_receiving_change(False)
        except Exception as e:
            self.info_signal.emit(str(e), 10000)

    def request_accept_incoming_file(self):
        try:
            self._network.start_receive_file_thread()
        except Exception as e:
            self.info_signal.emit(str(e), 10000)

    def request_reject_incoming_file(self):
        try:
            attempted = self._network.reject_file()

            if attempted:
                self._update_receive_label(False)
        except Exception as e:
            self._update_receive_label(False) # Still emit because the attempt happened
            self.info_signal.emit(str(e), 10000)

    def request_select_file(self, path: str):
        file_name = self._network.set_selected_file(path)
        self.selected_file_signal.emit(file_name)

    def request_send_selected_file(self):
        attempted = self._network.start_send_file_thread()

        if attempted:
            self.file_indicators_signal.emit()

    def request_connect(self, ip: str, port_str: str):
        # Validate Port
        try:
            port = int(port_str)

            if not (0 <= port <= 65535):
                raise ValueError
        except Exception:
            self.info_signal.emit("Port must be a number between 0 and 65535.", 10000)
            return

        # Validate IP
        # Handle localhost alias
        target_ip = ip.strip().lower()
        if target_ip == "localhost":
            target_ip = "127.0.0.1"

        try:
            ipaddress.ip_address(target_ip)
        except Exception:
            self.info_signal.emit(f"'{ip}' is not a valid IP address.", 10000)
            return

        status = self._network.start_request_connection_thread(target_ip, port)
        msg = ""

        if status == "STARTED":
            self.connecting_spinner_signal.emit(True)
            return
        elif status == "ALREADY_CONNECTING":
            return
        elif status == "SENDING_FILES":
            msg = "Cannot change connection when currently sending files."
        elif status == "RECEIVING_FILES":
            msg = "Cannot change connection when currently receiving files."
        elif status == "ALREADY_CONNECTED":
            msg = "Cannot change connection when already connected."

        self.info_signal.emit(msg, 10000)

    def request_add_contact(self, name: str, ip: str, port: int, fingerprint: str):
        self._contact_storage.add_contact(name, ip, port, fingerprint)

    def request_remove_contact(self, index: int):
        self._contact_storage.remove_contact(index)

    def request_edit_contact(self, index: int, field: str, new_value: str):
        # Convert port to int if that's the field being edited
        if field == "port":
            try:
                new_value = int(new_value)
            except Exception:
                return

        self._contact_storage.edit_contact(index, field, new_value)

    def request_exit(self):
        self._network.exit()

    ###########
    # Getters #
    ###########

    def get_host_info(self) -> HostInfo:
        return HostInfo(
            ip=self._network.host_external_ip,
            port=self._network.host_port,
            upnp_enabled=self._network.upnp_enabled,
        )

    def get_contacts(self) -> list:
        return self._contact_storage.contacts

    ###########
    # Other #
    ###########

    def _on_network_event(self, event: NetworkEvent):
        if event.type == "UPNP_UNAVAILABLE":
            self.info_signal.emit("UPNP is not enabled on network. Manual port mapping must be done for receiving to work.", 10000)

        elif event.type == "CONNECTION_LOST":
            self.info_signal.emit("An existing connection was terminated.", 10000)

            if event.message == "OUTBOUND":
                self._on_outbound_change(False)
                self.file_sent_signal.emit(False)
            elif event.message == "INBOUND":
                self._on_inbound_change(False)
                self._on_receiving_change(False)

        elif event.type == "FILE_SEND_FINISHED":
            self.file_sent_signal.emit(False)

            if event.message == "REJECTED":
                self._on_downloaded_change(False, self._network.selected_file.name)
            elif event.message == "ERROR":
                self.info_signal.emit("An error occurred while sending file.", 10000)

        elif event.type == "FILE_METADATA_SEND_FINISHED":
            status = False

            if event.message == "ACCEPTED":
                status = True
            elif event.message == "ERROR":
                self.info_signal.emit("An error occurred while sending file metadata.", 10000)

            self.file_sent_signal.emit(status)

        elif event.type == "FILE_DATA_SEND_PROGRESS":
            self.send_pgrs_bar_signal.emit(int(event.message))

        elif event.type == "FILE_DATA_SEND_FINISHED":
            if event.message == "SUCCESS":
                self._on_downloaded_change(True, self._network.selected_file.name)
            elif event.message == "ERROR":
                self.info_signal.emit("An error occurred while sending file data.", 10000)

        elif event.type == "FILE_METADATA_RECEIVE_FINISHED":
            if event.message == "SUCCESS":
                self._update_receive_label(True)
            elif event.message == "ERROR":
                self.info_signal.emit("An error occurred while receiving file metadata.", 10000)

        elif event.type == "FILE_DATA_RECEIVE_PROGRESS":
            self.receive_pgrs_bar_signal.emit(int(event.message))

        elif event.type == "FILE_DATA_RECEIVE_FINISHED":
            if event.message == "SUCCESS":
                self._update_receive_label(False)
            elif event.message == "ERROR":
                self.info_signal.emit("An error occurred while receiving file data.", 10000)

        elif event.type == "OUTBOUND_CONNECTION_REQUEST":
            status = False

            if event.message == "SUCCESS":
                status = True
            elif event.message == "CONNECTION_REFUSED":
                self.info_signal.emit("Connection was refused.", 10000)
            elif event.message == "CONNECTION_ERROR":
                self.info_signal.emit("Could not connect.", 10000)

            self._on_outbound_change(status)
            self.connecting_spinner_signal.emit(False)

        elif event.type == "INBOUND_CONNECTION_REQUEST":
            if event.message == "SUCCESS":
                self._on_inbound_change(True)
            elif event.message == "ERROR":
                self._on_inbound_change(False)
                self.info_signal.emit("Inbound connection request failed.", 10000)
