import os
import sys
from PyQt6 import QtWidgets
from PyQt6.QtWidgets import QFileDialog

from mainGUI import Ui_MainWindow
from network import Network


class Main:
    def __init__(self):
        self.window = None
        self.ui = None
        self.app = None
        self.clipboard = None  # The host's clipboard

        self.file_to_transfer = None  # The file to transfer

        self.network = Network()

    # Sets up the main window
    def window_setup(self):
        self.app = QtWidgets.QApplication(sys.argv)

        self.window = QtWidgets.QMainWindow()

        self.ui = Ui_MainWindow()
        self.ui.setupUi(self.window)

        self.setup_window_widgets()

        self.window.show()
        self.app.aboutToQuit.connect(self.exit)
        sys.exit(self.app.exec())

    # Sets up the widgets for the main window
    def setup_window_widgets(self):
        # Set up the clipboard for use
        self.clipboard = QtWidgets.QApplication.clipboard()

        self.ui.ipLabel.setText(f"Your IP: {self.network.host_public_ip}")

        self.ui.copyButton.clicked.connect(self.copy_user_ip_to_clipboard)
        self.ui.fileButton.clicked.connect(self.determine_file_to_transfer)

        self.ui.ipConfirmButton.clicked.connect(self.confirm_client_ip)
        self.ui.ipConfirmButton.clicked.connect(self.check_network_status_and_update_labels)

        self.ui.breakConnectionButton.clicked.connect(lambda: self.network.break_connection())
        self.ui.breakConnectionButton.clicked.connect(self.check_network_status_and_update_labels)

        self.ui.enableNetworkingButton.clicked.connect(lambda: self.network.enable_networking())
        self.ui.enableNetworkingButton.clicked.connect(self.check_network_status_and_update_labels)

        self.ui.disableNetworkingButton.clicked.connect(lambda: self.network.disable_networking())
        self.ui.disableNetworkingButton.clicked.connect(self.check_network_status_and_update_labels)

    # Used when program is about to exit
    def exit(self):
        self.network.exit()

    # Checks the network status, e.g. if networking is enabled, and updates labels
    def check_network_status_and_update_labels(self):
        if self.network.connected:
            self.ui.connectionLabel.setText(f"Connected to {self.network.client_public_ip}")
        else:
            self.ui.connectionLabel.setText("No connection")

        if self.network.networking_enabled:
            self.ui.networkingLabel.setText("Networking enabled")
        else:
            self.ui.networkingLabel.setText("Networking disabled")

        self.ui.statusbar.showMessage(self.network.exceptionMessage)
        self.network.exceptionMessage = ""

    # Copies the users IP to the clipboard
    def copy_user_ip_to_clipboard(self):
        self.clipboard.setText(self.network.host_public_ip)

    # Determines which file to transfer
    def determine_file_to_transfer(self):
        initial_dir = os.getcwd()

        # Returns a tuple where first element is path
        self.file_to_transfer = QFileDialog.getOpenFileName(self.window, "Choose file", initial_dir)
        self.ui.fileLabel.setText(f"Chosen file: {self.file_to_transfer[0]}")

    # Confirms the IP of the client
    def confirm_client_ip(self):
        ip = self.ui.ipLine.text()
        self.network.request_connection(ip)


if __name__ == "__main__":
    main = Main()
    main.window_setup()
