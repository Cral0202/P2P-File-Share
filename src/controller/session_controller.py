import ipaddress
import errno
import crypto.encryption as encryption

from PyQt6.QtCore import QObject, pyqtSignal
from storage.contact_storage import ContactStorage
from data_models.host_info import HostInfo

from network.network import Network, NetworkEvent
from updates.updates import program_version_up_to_date
from constants import GITHUB_LATEST_RELEASE_URL

class SessionController(QObject):
    initialized_signal: pyqtSignal = pyqtSignal()
    outbound_status_signal: pyqtSignal = pyqtSignal(str, bool)
    inbound_status_signal: pyqtSignal = pyqtSignal(str, bool)
    receiving_status_signal: pyqtSignal = pyqtSignal(str, bool)
    receive_pgrs_bar_signal: pyqtSignal = pyqtSignal(int)
    send_pgrs_bar_signal: pyqtSignal = pyqtSignal(int)
    download_signal: pyqtSignal = pyqtSignal(str)
    file_indicators_signal: pyqtSignal = pyqtSignal()
    connecting_spinner_signal: pyqtSignal = pyqtSignal(bool)
    file_sent_signal: pyqtSignal = pyqtSignal(bool)
    receive_label_signal: pyqtSignal = pyqtSignal(str, bool)
    info_signal: pyqtSignal = pyqtSignal(str, int)
    selected_file_signal: pyqtSignal = pyqtSignal(str)
    incoming_connection_signal: pyqtSignal = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self._network: Network = Network()
        self._contact_storage: ContactStorage = ContactStorage()

        self._is_up_to_date: bool = True # We keep this here so we can run the check during init (loading screen)

    def initialize(self):
        self._network.subscribe(self._on_network_event)
        self._network.initialize()
        self._is_up_to_date = program_version_up_to_date()

        self.initialized_signal.emit()

    def _on_outbound_change(self, connected: bool):
        if connected:
            _, name = self._contact_storage.check_if_contact_exists(self._network.outbound_peer_fingerprint)
            text = f"Outbound connection to: {name} ({self._network.outbound_peer_public_ip})"
        else:
            text = "No outbound connection"

        self.outbound_status_signal.emit(text, connected)

    def _on_inbound_change(self, connected: bool):
        if connected:
            _, name = self._contact_storage.check_if_contact_exists(self._network.inbound_peer_fingerprint)
            text = f"Inbound connection from: {name} ({self._network.inbound_peer_public_ip})"
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
        if reset_pgrs_bar and self._network.incoming_file:
            formatted_size = self._format_size(self._network.incoming_file.size)
            text = f"Ready to receive: {self._network.incoming_file.name} ({formatted_size})"
        else:
            text = "Ready to receive:"

        self.receive_label_signal.emit(text, reset_pgrs_bar)

    ############
    # Requests #
    ############

    def request_set_port(self, port: int):
        self._network.host_port = port

    def request_disconnect(self):
        attempted = self._network.break_connection()

        if attempted:
            self._on_outbound_change(False)

    def request_enable_receiving(self):
        error_msg = "Could not enable receiving."

        try:
            self._network.enable_receiving()
            self._on_receiving_change(True)
        except OSError as e:
            if e.errno == errno.EADDRINUSE:
                self.info_signal.emit(f"{error_msg} Port already in use.", 10000)
            else:
                self.info_signal.emit(error_msg, 10000)
        except Exception:
            self.info_signal.emit(error_msg, 10000)

    def request_disable_receiving(self):
        attempted = self._network.disable_receiving()

        if attempted:
            self._on_receiving_change(False)

    def request_accept_incoming_connection(self):
        self._network.accept_incoming_connection()

    def request_decline_incoming_connection(self):
        self._network.decline_incoming_connection()

    def request_accept_incoming_file(self):
        self._network.decide_on_file(True)

    def request_reject_incoming_file(self):
        attempted = self._network.decide_on_file(False)

        if attempted:
            self._update_receive_label(False)

    def request_select_file(self, path: str):
        file_name = self._network.set_selected_file(path)

        if file_name == "":
            return

        self.selected_file_signal.emit(file_name)

    def request_send_selected_file(self):
        attempted = self._network.send_file_metadata()

        if attempted:
            self.file_indicators_signal.emit()
            self.file_sent_signal.emit(True)

    def request_connect(self, ip: str, port_str: str, expected_fingerprint: str):
        # Validate Port
        try:
            port = int(port_str)

            if not (0 <= port <= 65535):
                raise ValueError
        except Exception:
            self.info_signal.emit("Port must be a number between 0 and 65535.", 10000)
            return

        # Validate IP
        try:
            ipaddress.ip_address(ip)
        except Exception:
            self.info_signal.emit(f"'{ip}' is not a valid IP address.", 10000)
            return

        status = self._network.start_request_connection_thread(ip, port, expected_fingerprint)
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

    def request_check_program_version(self):
        if not self._is_up_to_date:
            link = f"<a href='{GITHUB_LATEST_RELEASE_URL}'>Download</a>"
            self.info_signal.emit(f"New version available! {link}", 50000)

    def request_exit(self):
        self._network.exit()

    ###########
    # Getters #
    ###########

    def get_host_info(self) -> HostInfo:
        cert_path, _ = encryption.get_cert_and_key_path()

        return HostInfo(
            ip=self._network.host_external_ip,
            port=self._network.host_port,
            cert_fingerprint=encryption.get_cert_fingerprint(cert_path),
        )

    def get_contacts(self) -> list:
        return self._contact_storage.contacts

    ###########
    # Other #
    ###########

    def _on_network_event(self, event: NetworkEvent):
        if event.type == "CONNECTION_LOST":
            self.info_signal.emit("An existing connection was terminated.", 10000)

            if event.message == "OUTBOUND":
                self._on_outbound_change(False)
                self.file_sent_signal.emit(False)
                self.connecting_spinner_signal.emit(False)
                self.send_pgrs_bar_signal.emit(0)
            elif event.message == "INBOUND":
                self._on_inbound_change(False)
                self._update_receive_label(True)
                self.incoming_connection_signal.emit("Incoming connection from:")

        elif event.type == "FILE_SEND":
            if event.message == "FINISHED":
                self._on_downloaded_change(True, self._network.selected_file.name)
            elif event.message == "FILE_DECISION":
                self.file_sent_signal.emit(False)

                if event.details == "REJECTED":
                    self._on_downloaded_change(False, self._network.selected_file.name)
            elif event.message == "DATA_PROGRESS":
                self.send_pgrs_bar_signal.emit(int(event.details))

        elif event.type == "FILE_RECEIVE":
            if event.message == "METADATA_RECEIVED":
                self._update_receive_label(True)
            elif event.message == "FINISHED":
                self._update_receive_label(False)
            elif event.message == "DATA_PROGRESS":
                self.receive_pgrs_bar_signal.emit(int(event.details))

        elif event.type == "OUTBOUND_CONNECTION_REQUEST":
            status = False

            if event.message == "ACCEPTED":
                status = True
            elif event.message == "REFUSED":
                self.info_signal.emit("Connection was refused.", 10000)
            elif event.message == "INVALID_FINGERPRINT":
                self.info_signal.emit("Connection blocked due to fingerprint mismatch.", 10000)
            elif event.message == "ERROR":
                self.info_signal.emit("Could not connect.", 10000)

            self._on_outbound_change(status)
            self.connecting_spinner_signal.emit(False)

        elif event.type == "INBOUND_CONNECTION_REQUEST":
            if event.message == "ACCEPTED":
                self._on_inbound_change(True)
                self.incoming_connection_signal.emit("Incoming connection from:")
            elif event.message == "INCOMING":
                # Check if peer is in our contact list
                exists, name = self._contact_storage.check_if_contact_exists(self._network.inbound_peer_fingerprint)
                warning = " (WARNING)" if not exists else ""

                self.incoming_connection_signal.emit(f"Incoming connection from: {name}{warning} ({self._network.inbound_peer_public_ip})")
            elif event.message == "DECLINED":
                self.incoming_connection_signal.emit("Incoming connection from:")
            elif event.message == "ERROR":
                self._on_inbound_change(False)
                self.info_signal.emit("Inbound connection request failed.", 10000)

    def _format_size(self, size_bytes: int) -> str:
        if size_bytes == 0:
            return "0 B"

        units = ("B", "KB", "MB", "GB", "TB")

        # While the size is large enough to move to the next unit
        i = 0
        while size_bytes >= 1000 and i < len(units) - 1:
            size_bytes /= 1000
            i += 1

        formatted_num = f"{size_bytes:.2f}".rstrip('0').rstrip('.')
        return f"{formatted_num} {units[i]}"
