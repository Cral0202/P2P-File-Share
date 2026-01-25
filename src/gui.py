import os
import sys
from PyQt6 import QtWidgets
from PyQt6.QtGui import QIcon, QMovie
from PyQt6.QtWidgets import QFileDialog, QSizePolicy
from gui_layout import Ui_MainWindow
from network import Network
from session_controller import SessionController

GREEN_COLOR = "#4CAF50"
GREEN_COLOR_FORMATTED = f"color: {GREEN_COLOR}"
RED_COLOR = "red"
RED_COLOR_FORMATTED = f"color: {RED_COLOR}"

class GUIController:
    def __init__(self):
        self._window = None
        self._ui = None
        self._app = None
        self._clipboard = None

        self._spinner = None
        self._session_controller = SessionController(Network())

    # Sets up the main window
    def window_setup(self):
        self._app = QtWidgets.QApplication(sys.argv)
        self._app.setWindowIcon(QIcon(self._get_program_icon()))

        self._window = QtWidgets.QMainWindow()

        self._ui = Ui_MainWindow()
        self._ui.setupUi(self._window)

        self._setup_window_widgets()
        self._session_controller.initialize()

        self._window.show()
        self._app.aboutToQuit.connect(self._exit)
        sys.exit(self._app.exec())

    # Sets up the widgets for the main window
    def _setup_window_widgets(self):
        self._clipboard = QtWidgets.QApplication.clipboard()

        host_info = self._session_controller.get_host_info() # TODO: Currently runs before controller is initialized, so this is empty
        self._ui.ipLabel.setText(f"Your IP: {host_info.ip}")
        self._ui.ipLine.setPlaceholderText(f"{host_info.ip}:{host_info.port}")
        self._ui.ipLine.returnPressed.connect(self._on_connect_btn_pressed)  # Allow user to press enter

        self._ui.portSpinBox.setValue(host_info.port)
        self._ui.portSpinBox.valueChanged.connect(self._update_host_port)

        self._ui.copyButton.clicked.connect(self._copy_user_ip_and_port_to_clipboard)
        self._ui.chooseFileButton.clicked.connect(self._determine_file_to_transfer)

        self._ui.connectButton.clicked.connect(self._on_connect_btn_pressed)

        self._ui.disconnectButton.clicked.connect(self._session_controller.request_disconnect)

        self._ui.enableReceivingButton.clicked.connect(self._session_controller.request_enable_receiving)

        self._ui.disableReceivingButton.clicked.connect(self._session_controller.request_disable_receiving)

        self._ui.sendButton.clicked.connect(self._session_controller.request_send_selected_file)

        self._ui.receiveButton.clicked.connect(self._session_controller.request_accept_incoming_file)
        self._ui.rejectButton.clicked.connect(self._session_controller.request_reject_incoming_file)

        # Signals
        self._session_controller.receive_pgrs_bar_signal.connect(self._update_receive_progress_bar)
        self._session_controller.send_pgrs_bar_signal.connect(self._update_send_progress_bar)
        self._session_controller.spinner_signal.connect(self._toggle_spinner)
        self._session_controller.outbound_status_signal.connect(self._update_outbound_ui)
        self._session_controller.inbound_status_signal.connect(self._update_inbound_ui)
        self._session_controller.receiving_status_signal.connect(self._update_receiving_ui)
        self._session_controller.file_sent_signal.connect(self._toggle_file_sent_label)
        self._session_controller.receive_label_signal.connect(self._update_receive_label)
        self._session_controller.download_signal.connect(self._update_downloaded_label)
        self._session_controller.file_indicators_signal.connect(self._reset_file_indicators)
        self._session_controller.exception_signal.connect(self._show_exception_message)
        self._session_controller.selected_file_signal.connect(self._on_file_selected)

        # Set up spinner
        self._spinner = self._get_spinner_gif()
        self._ui.spinnerLabel.setMovie(self._spinner)
        self._toggle_spinner(False)

    # Used when program is about to exit
    def _exit(self):
        self._session_controller.request_exit()

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

    def _toggle_spinner(self, enable: bool):
        if enable:
            self._spinner.start()
            self._ui.spinnerLabel.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        else:
            self._spinner.stop()
            self._ui.spinnerLabel.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Ignored)

    def _show_exception_message(self, message: str, duration: int = 10000):
        self._ui.statusbar.showMessage(message, duration)

    def _update_host_port(self):
        port = self._ui.portSpinBox.value()
        self._session_controller.request_set_port(port)

    def _update_receiving_ui(self, text: str, enabled: bool):
        self._ui.receivingLabel.setText(text)
        self._ui.receivingLabel.setStyleSheet(GREEN_COLOR_FORMATTED if enabled else RED_COLOR_FORMATTED)

    def _update_outbound_ui(self, text: str, connected: bool):
        self._ui.outboundConnectionLabel.setText(text)
        self._ui.outboundConnectionLabel.setStyleSheet(GREEN_COLOR_FORMATTED if connected else RED_COLOR_FORMATTED)
        self._set_ip_line_edit_border_color(GREEN_COLOR if connected else RED_COLOR)

    def _update_inbound_ui(self, text: str, connected: bool):
        self._ui.inboundConnectionLabel.setText(text)
        self._ui.inboundConnectionLabel.setStyleSheet(GREEN_COLOR_FORMATTED if connected else RED_COLOR_FORMATTED)

    def _set_ip_line_edit_border_color(self, color: str):
        style_sheet = ("QLineEdit {{border: 2px solid #ccc; border-radius: 5px; "
                       "padding: 5px; color: white; border-color: {}}}".format(color))
        self._ui.ipLine.setStyleSheet(style_sheet)

    def _toggle_file_sent_label(self, show: bool):
        if show:
            self._ui.fileSentLabel.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        else:
            self._ui.fileSentLabel.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Ignored)

    def _update_receive_label(self, text: str, reset_pgrs_bar: bool):
        self._ui.readyToReceiveLabel.setText(text)

        if reset_pgrs_bar:
            self._update_receive_progress_bar(0)

    def _update_downloaded_label(self, text: str):
        self._ui.receiverDownloadedFileLabel.setText(text)
        self._ui.receiverDownloadedFileLabel.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)

    def _update_receive_progress_bar(self, progress: int):
        self._ui.receiveProgressBar.setValue(progress)

    def _update_send_progress_bar(self, progress: int):
        self._ui.sendProgressBar.setValue(progress)

    def _reset_file_indicators(self):
        self._ui.fileSentLabel.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Ignored)
        self._ui.receiverDownloadedFileLabel.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Ignored)
        self._ui.sendProgressBar.setValue(0)

    def _copy_user_ip_and_port_to_clipboard(self):
        host_info = self._session_controller.get_host_info()
        self._clipboard.setText(f"{host_info.ip}:{host_info.port}")

    def _determine_file_to_transfer(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self._window, "Choose file", os.getcwd()
        )

        if file_path:
            self._session_controller.request_select_file(file_path)

    def _on_file_selected(self, file_name: str):
        self._reset_file_indicators()
        self._ui.chosenFileLabel.setText(f"Chosen file: {file_name}")

    def _on_connect_btn_pressed(self):
        user_input = self._ui.ipLine.text().strip()
        self._session_controller.request_connect(user_input)
