import os
import sys
import threading

from PyQt6.QtGui import QIcon, QMovie
from PyQt6.QtWidgets import QFileDialog, QSizePolicy, QApplication, QMainWindow, QTableWidgetItem, QListWidgetItem
from PyQt6.QtCore import QSize

from .gui_layout import Ui_MainWindow
from controller.session_controller import SessionController

GREEN_COLOR: str = "#4CAF50"
GREEN_COLOR_FORMATTED: str = f"color: {GREEN_COLOR}"
RED_COLOR: str = "red"
RED_COLOR_FORMATTED: str = f"color: {RED_COLOR}"
CONTACT_FIELDS: list = ["name", "ip", "port", "fingerprint"]

class GUI():
    def __init__(self):
        self._window: QMainWindow | None = None
        self._ui: Ui_MainWindow | None = None
        self._app: QApplication | None = None
        self._clipboard: QApplication | None = None

        self._loading_screen_spinner: QMovie | None = None
        self._connecting_spinner: QMovie | None = None
        self._session_controller: SessionController = SessionController()

    # Sets up the main window
    def window_setup(self):
        self._app = QApplication(sys.argv)
        self._app.setWindowIcon(QIcon(self._resource_path("assets/icon.ico")))

        self._window = QMainWindow()

        self._ui = Ui_MainWindow()
        self._ui.setupUi(self._window)

        # Set up loading screen spinner
        self._loading_screen_spinner = QMovie(self._resource_path("assets/spinner.gif"))
        self._ui.loadingSpinnerLabel.setMovie(self._loading_screen_spinner)
        self._loading_screen_spinner.setScaledSize(QSize(64, 64))

        self._toggle_loading_screen_widgets(False)
        self._ui.stackedWidget.setCurrentWidget(self._ui.loadingPage)
        self._window.show()

        # We need to leave the main thread free, so we load the session controller in another thread
        self._session_controller.initialized_signal.connect(self._load_application_ui)
        threading.Thread(target=lambda: self._session_controller.initialize()).start()

        self._app.aboutToQuit.connect(self._exit)
        sys.exit(self._app.exec())

    def _load_application_ui(self):
        self._setup_window_widgets()
        self._populate_window_widgets()

        self._ui.stackedWidget.setCurrentWidget(self._ui.receivePage)
        self._toggle_loading_screen_widgets(True)

    # Sets up the widgets for the main window
    def _setup_window_widgets(self):
        self._clipboard = QApplication.clipboard()

        self._ui.portSpinBox.valueChanged.connect(self._update_host_port)
        self._ui.copyIPButton.clicked.connect(self._copy_ip_to_clipboard)
        self._ui.copyFingerprintButton.clicked.connect(self._copy_cert_fingerprint_to_clipboard)
        self._ui.selectFileButton.clicked.connect(self._determine_file_to_transfer)
        self._ui.connectButton.clicked.connect(self._on_connect_btn_pressed)
        self._ui.addContactButton.clicked.connect(self._add_contact)
        self._ui.removeContactButton.clicked.connect(self._remove_contact)
        self._ui.contactTable.itemChanged.connect(self._edit_contact)
        self._ui.disconnectButton.clicked.connect(self._session_controller.request_disconnect)
        self._ui.enableReceivingButton.clicked.connect(self._session_controller.request_enable_receiving)
        self._ui.disableReceivingButton.clicked.connect(self._session_controller.request_disable_receiving)
        self._ui.sendButton.clicked.connect(self._session_controller.request_send_selected_file)
        self._ui.receiveButton.clicked.connect(self._session_controller.request_accept_incoming_file)
        self._ui.rejectButton.clicked.connect(self._session_controller.request_reject_incoming_file)
        self._ui.acceptConnectionButton.clicked.connect(self._session_controller.request_accept_incoming_connection)
        self._ui.declineConnectionButton.clicked.connect(self._session_controller.request_decline_incoming_connection)

        # Signals
        self._session_controller.receive_pgrs_bar_signal.connect(self._update_receive_progress_bar)
        self._session_controller.send_pgrs_bar_signal.connect(self._update_send_progress_bar)
        self._session_controller.connecting_spinner_signal.connect(self._toggle_connecting_spinner)
        self._session_controller.outbound_status_signal.connect(self._update_outbound_ui)
        self._session_controller.inbound_status_signal.connect(self._update_inbound_ui)
        self._session_controller.receiving_status_signal.connect(self._update_receiving_ui)
        self._session_controller.file_sent_signal.connect(self._toggle_file_sent_label)
        self._session_controller.receive_label_signal.connect(self._update_receive_label)
        self._session_controller.download_signal.connect(self._update_downloaded_label)
        self._session_controller.file_indicators_signal.connect(self._reset_file_indicators)
        self._session_controller.info_signal.connect(self._show_info_message)
        self._session_controller.selected_file_signal.connect(self._on_file_selected)
        self._session_controller.incoming_connection_signal.connect(self._on_incoming_connection_change)

        # The connecting spinner
        self._connecting_spinner = QMovie(self._resource_path("assets/spinner.gif"))
        self._ui.connectingSpinnerLabel.setMovie(self._connecting_spinner)
        self._toggle_connecting_spinner(False)
        self._connecting_spinner.setScaledSize(QSize(32, 32))

        # Sidebar
        items = [
            ("Receiving", self._resource_path("assets/sidebar/receive.png")),
            ("Sending", self._resource_path("assets/sidebar/send.png")),
        ]

        for text, icon_path in items:
            item = QListWidgetItem(QIcon(icon_path), "")
            item.setToolTip(text)
            self._ui.sidebar.addItem(item)

        self._ui.sidebar.currentRowChanged.connect(
            self._ui.stackedWidget.setCurrentIndex
        )

    def _populate_window_widgets(self):
        # Load host info
        host_info = self._session_controller.get_host_info()

        self._ui.ipLabel.setText(f"Your IP address: {host_info.ip}")
        self._ui.portSpinBox.setValue(host_info.port)
        self._ui.fingerprintLabel.setText(f"Your fingerprint: {host_info.cert_fingerprint}")

        # Load contacts
        contacts = self._session_controller.get_contacts()
        self._ui.contactTable.blockSignals(True) # Block signals so we don't trigger "_edit_contact"

        for contact in contacts:
            row = self._ui.contactTable.rowCount()
            self._ui.contactTable.insertRow(row)

            self._ui.contactTable.setItem(row, 0, QTableWidgetItem(contact.get(CONTACT_FIELDS[0], "")))
            self._ui.contactTable.setItem(row, 1, QTableWidgetItem(contact.get(CONTACT_FIELDS[1], "")))
            self._ui.contactTable.setItem(row, 2, QTableWidgetItem(str(contact.get(CONTACT_FIELDS[2], ""))))
            self._ui.contactTable.setItem(row, 3, QTableWidgetItem(contact.get(CONTACT_FIELDS[3], "")))

        self._ui.contactTable.blockSignals(False)

    def _toggle_loading_screen_widgets(self, show: bool):
        # TODO: Should add a widget instead and just show/hide it, but for some reason the widget breaks
        if show:
            self._loading_screen_spinner.stop()
            self._ui.sidebar.show()
            self._ui.bottomLine.show()
            self._ui.inboundConnectionLabel.show()
            self._ui.outboundConnectionLabel.show()
            self._ui.receivingLabel.show()
        else:
            self._loading_screen_spinner.start()
            self._ui.sidebar.hide()
            self._ui.bottomLine.hide()
            self._ui.inboundConnectionLabel.hide()
            self._ui.outboundConnectionLabel.hide()
            self._ui.receivingLabel.hide()

    # Used when program is about to exit
    def _exit(self):
        self._session_controller.request_exit()

    def _resource_path(self, relative_path: str) -> str:
        try:
            # PyInstaller
            base_path = sys._MEIPASS
        except AttributeError:
            # Normal
            base_path = os.path.abspath(".")

        return os.path.join(base_path, relative_path)

    def _toggle_connecting_spinner(self, enable: bool):
        if enable:
            self._connecting_spinner.start()
            self._ui.connectingSpinnerLabel.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        else:
            self._connecting_spinner.stop()
            self._ui.connectingSpinnerLabel.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Ignored)

    def _show_info_message(self, message: str, duration: int):
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

    def _update_inbound_ui(self, text: str, connected: bool):
        self._ui.inboundConnectionLabel.setText(text)
        self._ui.inboundConnectionLabel.setStyleSheet(GREEN_COLOR_FORMATTED if connected else RED_COLOR_FORMATTED)

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

    def _copy_ip_to_clipboard(self):
        # TODO: Grab directly from UI instead?
        host_info = self._session_controller.get_host_info()
        self._clipboard.setText(host_info.ip)

    def _copy_cert_fingerprint_to_clipboard(self):
        # TODO: Grab directly from UI instead?
        host_info = self._session_controller.get_host_info()
        self._clipboard.setText(host_info.cert_fingerprint)

    def _determine_file_to_transfer(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self._window, "Choose file", os.getcwd()
        )

        if file_path:
            self._session_controller.request_select_file(file_path)

    def _on_file_selected(self, file_name: str):
        self._reset_file_indicators()
        self._ui.selectedFileLabel.setText(f"Selected file: {file_name}")

    def _on_connect_btn_pressed(self):
        selected_row = self._ui.contactTable.currentRow()

        if selected_row == -1:
            return

        ip = self._ui.contactTable.item(selected_row, 1).text()
        port = self._ui.contactTable.item(selected_row, 2).text()
        fingerprint = self._ui.contactTable.item(selected_row, 3).text()

        self._session_controller.request_connect(ip, port, fingerprint)

    def _on_incoming_connection_change(self, text):
        self._ui.incomingConnectionLabel.setText(text)

    def _add_contact(self):
        name, ip, port, fp = "New Contact", "0.0.0.0", 35555, "PASTE_FINGERPRINT"

        self._session_controller.request_add_contact(name, ip, port, fp)
        self._ui.contactTable.blockSignals(True) # Block signals so we don't trigger "_edit_contact"

        row = self._ui.contactTable.rowCount()
        self._ui.contactTable.insertRow(row)
        self._ui.contactTable.setItem(row, 0, QTableWidgetItem(name))
        self._ui.contactTable.setItem(row, 1, QTableWidgetItem(ip))
        self._ui.contactTable.setItem(row, 2, QTableWidgetItem(str(port)))
        self._ui.contactTable.setItem(row, 3, QTableWidgetItem(fp))

        self._ui.contactTable.blockSignals(False)

    def _remove_contact(self):
        current_row = self._ui.contactTable.currentRow()
        if current_row > -1: # Ensure something is actually selected
            self._session_controller.request_remove_contact(current_row)
            self._ui.contactTable.removeRow(current_row)

    def _edit_contact(self, item: QTableWidgetItem):
        row = item.row()
        column = item.column()
        new_value = item.text()

        field_name = CONTACT_FIELDS[column]
        self._session_controller.request_edit_contact(row, field_name, new_value)
