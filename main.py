import os
import sys
from PyQt6 import QtWidgets
from PyQt6.QtWidgets import QFileDialog, QSizePolicy
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
        self.ui.ipLine.returnPressed.connect(self.confirm_client_ip)  # Allow user to press enter

        self.ui.copyButton.clicked.connect(self.copy_user_ip_to_clipboard)
        self.ui.chooseFileButton.clicked.connect(self.determine_file_to_transfer)

        self.ui.connectButton.clicked.connect(self.confirm_client_ip)

        self.ui.disconnectButton.clicked.connect(lambda: self.network.break_connection())

        self.ui.enableReceivingButton.clicked.connect(lambda: self.network.enable_receiving())

        self.ui.disableReceivingButton.clicked.connect(lambda: self.network.disable_receiving())

        self.ui.sendButton.clicked.connect(lambda: self.network.start_send_file_thread(self.file_to_transfer["name"],
                                                                                       self.file_to_transfer["size"],
                                                                                       self.file_to_transfer["path"]))

        self.ui.receiveButton.clicked.connect(lambda: self.network.start_receive_file_thread())

        # Connect the signals
        self.network.receive_progress_bar_signal.connect(self.update_receive_progress_bar)
        self.network.send_progress_bar_signal.connect(self.update_send_progress_bar)
        self.network.connection_indicator_signal.connect(self.update_connection_indicators)
        self.network.receiving_allowed_indicator_signal.connect(self.update_receiving_allowed_label)
        self.network.file_sent_indicator_signal.connect(self.update_file_sent_label)
        self.network.file_ready_to_receive_signal.connect(self.update_receive_label)
        self.network.sent_file_has_been_downloaded_signal.connect(self.update_sent_file_has_been_downloaded_label)
        self.network.exception_signal.connect(self.show_exception_message)

        # Display warning if upnp is not enabled on network
        if not self.network.upnp_enabled:
            self.show_exception_message("UPNP is not enabled on network. Manual port mapping must be done for receiving"
                                        " to work.")

    # Used when program is about to exit
    def exit(self):
        self.network.exit()

    # Shows an exception message
    def show_exception_message(self, message):
        self.ui.statusbar.showMessage(message, 5000)  # Show the message for a specific amount of time

    # Updates the receiving label to the relevant status
    def update_receiving_allowed_label(self, status):
        if status:
            self.ui.receivingLabel.setText("Receiving enabled")
            self.ui.receivingLabel.setStyleSheet("color: #4CAF50")
        else:
            self.ui.receivingLabel.setText("Receiving disabled")
            self.ui.receivingLabel.setStyleSheet("color: red")

    # Updates the connection indicators to the relevant status
    def update_connection_indicators(self, status):
        if status:
            self.ui.connectionLabel.setText(f"Connected to: {self.network.client_public_ip}")
            self.ui.connectionLabel.setStyleSheet("color: #4CAF50")
            self.set_ip_line_edit_border_color("#4CAF50")
        else:
            self.ui.connectionLabel.setText("No connection")
            self.ui.connectionLabel.setStyleSheet("color: red")
            self.set_ip_line_edit_border_color("red")

    # Sets the border color of the ip line edit
    def set_ip_line_edit_border_color(self, color):
        style_sheet = ("QLineEdit {{border: 2px solid #ccc; border-radius: 5px; "
                       "padding: 5px; color: white; border-color: {}}}".format(color))
        self.ui.ipLine.setStyleSheet(style_sheet)

    # Updates the file sent label
    def update_file_sent_label(self):
        self.ui.fileSentLabel.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)

    def update_receive_label(self, file_name):
        self.ui.readyToReceiveLabel.setText(f"Ready to receive: {file_name}")

    # Updates the sent file has been downloaded label
    def update_sent_file_has_been_downloaded_label(self, file_name):
        self.ui.receiverDownloadedFileLabel.setText(f"The sent file \"{file_name}\" has been downloaded by the "
                                                    f"receiver.")
        self.ui.receiverDownloadedFileLabel.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)

    # Updates the receive progress bar
    def update_receive_progress_bar(self, progress):
        self.ui.receiveProgressBar.setValue(int(progress))

    # Updates the send progress bar
    def update_send_progress_bar(self, progress):
        self.ui.sendProgressBar.setValue(int(progress))

    # Resets the file indicators, e.g. the file sent label
    def reset_file_indicators(self):
        self.ui.fileSentLabel.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Ignored)
        self.ui.receiverDownloadedFileLabel.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Ignored)
        self.ui.sendProgressBar.setValue(0)

    # Copies the users IP to the clipboard
    def copy_user_ip_to_clipboard(self):
        self.clipboard.setText(self.network.host_external_ip)

    # Determines which file to transfer
    def determine_file_to_transfer(self):
        initial_dir = os.getcwd()

        file_path_unformatted = QFileDialog.getOpenFileName(self.window, "Choose file", initial_dir)  # Returns a tuple
        file_path = file_path_unformatted[0]  # First element in tuple is path

        # Set metadata for the file
        if file_path:
            self.reset_file_indicators()
            file_name = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)

            self.file_to_transfer = {
                "path": file_path,
                "name": file_name,
                "size": file_size
            }

            self.ui.chosenFileLabel.setText(f"Chosen file: {file_name}")

    # Confirms the IP of the client
    def confirm_client_ip(self):
        ip = self.ui.ipLine.text()
        self.network.request_connection(ip)


if __name__ == "__main__":
    main = Main()
    main.window_setup()
