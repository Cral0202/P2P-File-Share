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
        self.clipboard = QtWidgets.QApplication.clipboard()

        self.ui.ipLabel.setText(f"Your IP: {self.network.host_external_ip}")

        self.ui.copyButton.clicked.connect(self.copy_user_ip_to_clipboard)
        self.ui.fileButton.clicked.connect(self.determine_file_to_transfer)

        self.ui.ipConfirmButton.clicked.connect(self.confirm_client_ip)
        self.ui.ipConfirmButton.clicked.connect(self.check_network_status_and_update_labels)

        self.ui.breakConnectionButton.clicked.connect(lambda: self.network.break_connection())
        self.ui.breakConnectionButton.clicked.connect(self.check_network_status_and_update_labels)

        self.ui.enableReceivingButton.clicked.connect(lambda: self.network.enable_networking())
        self.ui.enableReceivingButton.clicked.connect(self.check_network_status_and_update_labels)

        self.ui.disableReceivingButton.clicked.connect(lambda: self.network.disable_networking())
        self.ui.disableReceivingButton.clicked.connect(self.check_network_status_and_update_labels)

        self.ui.sendButton.clicked.connect(lambda: self.network.start_send_file_thread(self.file_to_transfer["name"],
                                                                                       self.file_to_transfer["size"],
                                                                                       self.file_to_transfer["path"]))
        self.ui.sendButton.clicked.connect(self.check_network_status_and_update_labels)

        self.ui.receiveButton.clicked.connect(lambda: self.network.start_receive_file_thread())
        self.ui.receiveButton.clicked.connect(self.check_network_status_and_update_labels)

        self.network.progress_bar_signal.connect(self.update_progress_bar)
        self.ui.progressBar.setValue(0)

        self.ui.statusbar.showMessage(self.network.exceptionMessage)

    # Used when program is about to exit
    def exit(self):
        self.network.exit()

    # Checks the network status, e.g. if receiving is enabled, and updates labels
    def check_network_status_and_update_labels(self):
        if self.network.connected:
            self.ui.connectionLabel.setText(f"Connected to: {self.network.client_public_ip}")
            self.ui.connectionLabel.setStyleSheet("color: green")
        else:
            self.ui.connectionLabel.setText("No connection")
            self.ui.connectionLabel.setStyleSheet("color: red")

        if self.network.receiving_enabled:
            self.ui.receivingLabel.setText("Receiving enabled")
            self.ui.receivingLabel.setStyleSheet("color: green")
        else:
            self.ui.receivingLabel.setText("Receiving disabled")
            self.ui.receivingLabel.setStyleSheet("color: red")

        self.ui.statusbar.showMessage(self.network.exceptionMessage)
        self.network.exceptionMessage = ""

    # Copies the users IP to the clipboard
    def copy_user_ip_to_clipboard(self):
        self.clipboard.setText(self.network.host_external_ip)

    # Determines which file to transfer
    def determine_file_to_transfer(self):
        initial_dir = os.getcwd()

        file_path_unformatted = QFileDialog.getOpenFileName(self.window, "Choose file", initial_dir)  # Returns a tuple
        file_path = file_path_unformatted[0]  # First element in tuple is path
        self.ui.fileLabel.setText(f"Chosen file: {file_path}")

        # Set metadata for the file
        if file_path:
            file_name = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)

            self.file_to_transfer = {
                "path": file_path,
                "name": file_name,
                "size": file_size
            }

    # Confirms the IP of the client
    def confirm_client_ip(self):
        ip = self.ui.ipLine.text()
        self.network.request_connection(ip)

    # Updates the progress bar
    def update_progress_bar(self, progress):
        self.ui.progressBar.setValue(int(progress))


if __name__ == "__main__":
    main = Main()
    main.window_setup()
