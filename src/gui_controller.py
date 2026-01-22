import os
import sys
from PyQt6 import QtWidgets
from PyQt6.QtGui import QIcon, QMovie
from PyQt6.QtWidgets import QFileDialog, QSizePolicy
from main_gui import Ui_MainWindow
from network import Network

GREEN_COLOR = "#4CAF50"
GREEN_COLOR_FORMATTED = f"color: {GREEN_COLOR}"
RED_COLOR = "red"
RED_COLOR_FORMATTED = f"color: {RED_COLOR}"

class GUIController:
    def __init__(self):
        self._window = None
        self._ui = None
        self._app = None
        self._clipboard = None  # The host's clipboard

        self._spinner = None

        self._file_to_transfer = {
            "file_path": None,
            "file_name": None,
            "file_size": None,
        }

        self._network = Network()

    # Sets up the main window
    def window_setup(self):
        self._app = QtWidgets.QApplication(sys.argv)
        self._app.setWindowIcon(QIcon(self._get_program_icon()))

        self._window = QtWidgets.QMainWindow()

        self._ui = Ui_MainWindow()
        self._ui.setupUi(self._window)

        self._setup_window_widgets()

        self._window.show()
        self._app.aboutToQuit.connect(self._exit)
        sys.exit(self._app.exec())

    # Sets up the widgets for the main window
    def _setup_window_widgets(self):
        self._clipboard = QtWidgets.QApplication.clipboard()

        self._ui.ipLabel.setText(f"Your IP: {self._network.host_external_ip}")
        self._ui.ipLine.setPlaceholderText(f"{self._network.host_external_ip}:{self._network.host_port}")
        self._ui.ipLine.returnPressed.connect(self._confirm_client_ip)  # Allow user to press enter

        self._ui.portSpinBox.setValue(self._network.host_port)
        self._ui.portSpinBox.valueChanged.connect(self._update_host_port)

        self._ui.copyButton.clicked.connect(self._copy_user_ip_and_port_to_clipboard)
        self._ui.chooseFileButton.clicked.connect(self._determine_file_to_transfer)

        self._ui.connectButton.clicked.connect(self._confirm_client_ip)

        self._ui.disconnectButton.clicked.connect(lambda: self._network.break_connection())

        self._ui.enableReceivingButton.clicked.connect(lambda: self._network.enable_receiving())

        self._ui.disableReceivingButton.clicked.connect(lambda: self._network.disable_receiving())

        self._ui.sendButton.clicked.connect(
            lambda: self._network.start_send_file_thread(
                self._file_to_transfer["file_path"],
                self._file_to_transfer["file_name"],
                self._file_to_transfer["file_size"]
            )
        )

        self._ui.receiveButton.clicked.connect(lambda: self._network.start_receive_file_thread())

        self._ui.rejectButton.clicked.connect(lambda: self._network.reject_file())

        # Connect the signals
        self._network.receive_progress_bar_signal.connect(self._update_receive_progress_bar)
        self._network.send_progress_bar_signal.connect(self._update_send_progress_bar)
        self._network.spinner_signal.connect(self._toggle_spinner)
        self._network.outbound_connection_indicator_signal.connect(self._update_outbound_connection_indicators)
        self._network.inbound_connection_indicator_signal.connect(self._update_inbound_connection_indicators)
        self._network.receiving_allowed_indicator_signal.connect(self._update_receiving_allowed_label)
        self._network.file_sent_indicator_signal.connect(self._update_file_sent_label)
        self._network.file_ready_to_receive_signal.connect(self._update_receive_label)
        self._network.sent_file_has_been_downloaded_signal.connect(self._update_sent_file_has_been_downloaded_label)
        self._network.reset_file_indicators_signal.connect(self._reset_file_indicators)
        self._network.exception_signal.connect(self._show_exception_message)

        # Set up spinner
        self._spinner = self._get_spinner_gif()
        self._ui.spinnerLabel.setMovie(self._spinner)
        self._toggle_spinner(False)

        # Display warning if upnp is not enabled on network
        if not self._network.upnp_enabled:
            self._show_exception_message("WARNING: UPNP is not enabled on network. Manual port mapping must be done "
                                        "for receiving to work.")

    # Used when program is about to exit
    def _exit(self):
        self._network.exit()

    # Gets the program icon (done this way because of pyinstaller)
    def _get_program_icon(self):
        root = os.path.dirname(__file__)
        program_icon = os.path.join(root, "../assets/icon.ico")
        return program_icon

    # Gets the spinner gif (done this way because of pyinstaller)
    def _get_spinner_gif(self):
        root = os.path.dirname(__file__)
        spinner_gif = os.path.join(root, "../assets/spinner.gif")
        return QMovie(spinner_gif)

    # Toggles the spinner
    def _toggle_spinner(self, status: bool):
        if status:
            self._spinner.start()
            self._ui.spinnerLabel.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        else:
            self._spinner.stop()
            self._ui.spinnerLabel.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Ignored)

    # Shows an exception message for a specific amount of time
    def _show_exception_message(self, message: str):
        self._ui.statusbar.showMessage(message, 10000)

    # Updates the host port to chosen value
    def _update_host_port(self):
        new_port = self._ui.portSpinBox.value()
        self._network.host_port = new_port

    # Updates the receiving label to the relevant status
    def _update_receiving_allowed_label(self, status: bool):
        if status:
            self._ui.receivingLabel.setText("Receiving enabled")
            self._ui.receivingLabel.setStyleSheet(GREEN_COLOR_FORMATTED)
        else:
            self._ui.receivingLabel.setText("Receiving disabled")
            self._ui.receivingLabel.setStyleSheet(RED_COLOR_FORMATTED)

    # Updates the outbound connection indicators to the relevant status
    def _update_outbound_connection_indicators(self, status: bool):
        if status:
            self._ui.outboundConnectionLabel.setText(f"Outbound connection to: {self._network.outbound_peer_public_ip}")
            self._ui.outboundConnectionLabel.setStyleSheet(GREEN_COLOR_FORMATTED)
            self._set_ip_line_edit_border_color(GREEN_COLOR)
        elif not status and not self._network.outbound_connection:
            self._ui.outboundConnectionLabel.setText("No outbound connection")
            self._ui.outboundConnectionLabel.setStyleSheet(RED_COLOR_FORMATTED)
            self._set_ip_line_edit_border_color(RED_COLOR)

    # Updates the inbound connection indicators to the relevant status
    def _update_inbound_connection_indicators(self, status: bool):
        if status:
            self._ui.inboundConnectionLabel.setText(f"Inbound connection from: {self._network.inbound_peer_public_ip}")
            self._ui.inboundConnectionLabel.setStyleSheet(GREEN_COLOR_FORMATTED)
        elif not status:
            self._ui.inboundConnectionLabel.setText("No inbound connection")
            self._ui.inboundConnectionLabel.setStyleSheet(RED_COLOR_FORMATTED)

    # Sets the border color of the ip line edit
    def _set_ip_line_edit_border_color(self, color: str):
        style_sheet = ("QLineEdit {{border: 2px solid #ccc; border-radius: 5px; "
                       "padding: 5px; color: white; border-color: {}}}".format(color))
        self._ui.ipLine.setStyleSheet(style_sheet)

    # Updates the file sent label
    def _update_file_sent_label(self, status: bool):
        if status:
            self._ui.fileSentLabel.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        else:
            self._ui.fileSentLabel.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Ignored)

    def _update_receive_label(self, status: bool):
        if status:
            self._ui.readyToReceiveLabel.setText(f"Ready to receive: {self._network.file_to_be_received_name}")
            self._update_receive_progress_bar(0)
        else:
            self._ui.readyToReceiveLabel.setText(f"Ready to receive:")

    # Updates the sent file has been downloaded label
    def _update_sent_file_has_been_downloaded_label(self, status: bool, file_name: str):
        if status:
            self._ui.receiverDownloadedFileLabel.setText(f"The sent file \"{file_name}\" has been downloaded by the "
                                                    f"receiver.")
        else:
            self._ui.receiverDownloadedFileLabel.setText(f"The sent file \"{file_name}\" was REJECTED by the "
                                                        f"receiver.")

        self._ui.receiverDownloadedFileLabel.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)

    # Updates the receive progress bar
    def _update_receive_progress_bar(self, progress: int):
        self._ui.receiveProgressBar.setValue(progress)

    # Updates the send progress bar
    def _update_send_progress_bar(self, progress: int):
        self._ui.sendProgressBar.setValue(progress)

    # Resets the file indicators, e.g. the file sent label
    def _reset_file_indicators(self):
        self._ui.fileSentLabel.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Ignored)
        self._ui.receiverDownloadedFileLabel.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Ignored)
        self._ui.sendProgressBar.setValue(0)

    # Copies the users IP + Port to the clipboard
    def _copy_user_ip_and_port_to_clipboard(self):
        self._clipboard.setText(f"{self._network.host_external_ip}:{self._network.host_port}")

    # Determines which file to transfer
    def _determine_file_to_transfer(self):
        try:
            initial_dir = os.getcwd()

            # Returns a tuple where first element is path
            file_path_unformatted = QFileDialog.getOpenFileName(self._window, "Choose file", initial_dir)
            file_path = file_path_unformatted[0]

            # Set metadata for the file
            if file_path:
                self._reset_file_indicators()
                file_name = os.path.basename(file_path)
                file_size = os.path.getsize(file_path)

                self._file_to_transfer = {
                    "file_path": file_path,
                    "file_name": file_name,
                    "file_size": file_size,
                }

                self._ui.chosenFileLabel.setText(f"Chosen file: {file_name}")
        except Exception as e:
            self._show_exception_message(f"An error occurred: {e}")

    # Confirms the IP of the client
    def _confirm_client_ip(self):
        try:
            user_input = self._ui.ipLine.text()
            ip, port = user_input.split(":")  # Extract the IP and port
            port = int(port)
            self._network.start_request_connection_thread(ip, port)
        except Exception:
            self._show_exception_message("IP-address input is invalid.")
