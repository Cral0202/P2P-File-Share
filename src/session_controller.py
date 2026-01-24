import os
from PyQt6.QtCore import QObject, pyqtSignal
from network import Network, NetworkEvent
from models.transfer_file import TransferFile
from models.host_info import HostInfo

class SessionController(QObject):
    outbound_status_changed = pyqtSignal(str, bool)
    inbound_status_changed = pyqtSignal(str, bool)
    receiving_status_changed = pyqtSignal(str, bool)
    receive_pgrs_bar_changed = pyqtSignal(int)
    send_pgrs_bar_changed = pyqtSignal(int)
    download_changed = pyqtSignal(str)
    should_reset_file_indicators = pyqtSignal()
    should_toggle_spinner = pyqtSignal(bool)
    should_toggle_file_sent = pyqtSignal(bool)
    should_update_receive_label = pyqtSignal(str, bool)
    exception_signal = pyqtSignal(str, int)
    file_selected = pyqtSignal(str)

    def __init__(self, network: Network):
        super().__init__()
        self._network = network

        # Signals
        self._network.outbound_connection_indicator_signal.connect(self._on_outbound_change)
        self._network.inbound_connection_indicator_signal.connect(self._on_inbound_change)
        self._network.receive_progress_bar_signal.connect(self._on_receive_pgrs_bar_change)
        self._network.send_progress_bar_signal.connect(self._on_send_pgrs_bar_change)
        self._network.sent_file_has_been_downloaded_signal.connect(self._on_downloaded_change)
        self._network.reset_file_indicators_signal.connect(self._reset_file_indicators)
        self._network.spinner_signal.connect(self._toggle_spinner)
        self._network.file_sent_indicator_signal.connect(self._toggle_file_sent)
        self._network.file_ready_to_receive_signal.connect(self._update_receive_label)
        self._network.exception_signal.connect(self._show_exception_message)

    def initialize(self):
        self._network.subscribe(self._on_network_event)
        self._network.initialize()

    def _on_outbound_change(self, connected: bool):
        if connected:
            text = f"Outbound connection to: {self._network.outbound_peer_public_ip}"
        else:
            text = "No outbound connection"

        self.outbound_status_changed.emit(text, connected)

    def _on_inbound_change(self, connected: bool):
        if connected:
            text = f"Inbound connection from: {self._network.inbound_peer_public_ip}"
        else:
            text = "No inbound connection"

        self.inbound_status_changed.emit(text, connected)

    def _on_receiving_change(self, enabled: bool):
        if enabled:
            text = "Receiving enabled"
        else:
            text = "Receiving disabled"

        self.receiving_status_changed.emit(text, enabled)

    def _on_receive_pgrs_bar_change(self, progress: int):
        self.receive_pgrs_bar_changed.emit(progress)

    def _on_send_pgrs_bar_change(self, progress: int):
        self.send_pgrs_bar_changed.emit(progress)

    def _on_downloaded_change(self, downloaded: bool, file_name: str):
        if downloaded:
            text = f"The sent file \"{file_name}\" has been downloaded by the receiver."
        else:
            text = f"The sent file \"{file_name}\" was rejected by the receiver."

        self.download_changed.emit(text)

    def _reset_file_indicators(self):
        self.should_reset_file_indicators.emit()

    def _toggle_spinner(self, enable: bool):
        self.should_toggle_spinner.emit(enable)

    def _toggle_file_sent(self, show: bool):
        self.should_toggle_file_sent.emit(show)

    def _update_receive_label(self, reset_pgrs_bar: bool):
        if reset_pgrs_bar:
            text = f"Ready to receive: {self._network.incoming_file.name}"
        else:
            text = "Ready to receive:"

        self.should_update_receive_label.emit(text, reset_pgrs_bar)

    # TODO: Remove
    def _show_exception_message(self, message: str, duration: int = 10000):
        self.exception_signal.emit(message, duration)

    ############
    # Requests #
    ############

    def request_set_port(self, port: int):
        self._network.host_port = port

    def request_disconnect(self):
        self._network.break_connection()

    def request_enable_receiving(self):
        try:
            self._network.enable_receiving()
            self._on_receiving_change(True)
        except Exception as e:
            self.exception_signal.emit(str(e), 10000)

    def request_disable_receiving(self):
        try:
            self._network.disable_receiving()
            self._on_receiving_change(False)
        except Exception as e:
            self.exception_signal.emit(str(e), 10000)

    def request_accept_incoming_file(self):
        self._network.start_receive_file_thread()

    def request_reject_incoming_file(self):
        self._network.reject_file()

    def request_select_file(self, path: str):
        file = TransferFile(
            path = path,
            name = os.path.basename(path),
            size = os.path.getsize(path),
        )

        self._network.selected_file = file
        self.file_selected.emit(file.name)

    def request_send_selected_file(self):
        self._network.start_send_file_thread()

    def request_connect(self, text: str):
        try:
            ip, port_str = text.split(":") # Extract the IP and port
            port = int(port_str)
        except Exception:
            self._show_exception_message("IP-address input is invalid.")
            return

        self._network.start_request_connection_thread(ip, port)

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

    ###########
    # Other #
    ###########

    def _on_network_event(self, event: NetworkEvent):
        if event.type == "UPNP_UNAVAILABLE":
            self.exception_signal.emit("UPNP is not enabled on network. Manual port mapping must be done "
                                        "for receiving to work.", 10000)
