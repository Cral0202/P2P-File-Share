import logging
import os
import sys
from PyQt6 import QtWidgets
from PyQt6.QtGui import QIcon, QMovie
from PyQt6.QtWidgets import QFileDialog, QSizePolicy
from main_gui import Ui_MainWindow
from network import Network
from file_metadata import FileMetadata


class GUIController:
    def __init__(self):
        self.window = None
        self.ui = None
        self.app = None
        self.clipboard = None  # The host's clipboard

        self.green_color = "#4CAF50"
        self.green_color_formatted = f"color: {self.green_color}"
        self.red_color = "red"
        self.red_color_formatted = f"color: {self.red_color}"

        self.spinner = None
        self.file_to_transfer = FileMetadata("None", "None", "None")

        self.network = Network()

    # Sets up the main window
    def window_setup(self):
        self.app = QtWidgets.QApplication(sys.argv)
        self.app.setWindowIcon(QIcon(self.get_program_icon()))

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
        self.ui.ipLine.setPlaceholderText(f"{self.network.host_external_ip}:{self.network.host_port}")
        self.ui.ipLine.returnPressed.connect(self.confirm_client_ip)  # Allow user to press enter

        self.ui.portSpinBox.setValue(self.network.host_port)
        self.ui.portSpinBox.valueChanged.connect(self.update_host_port)

        self.ui.copyButton.clicked.connect(self.copy_user_ip_to_clipboard)
        self.ui.chooseFileButton.clicked.connect(self.determine_file_to_transfer)

        self.ui.connectButton.clicked.connect(self.confirm_client_ip)

        self.ui.disconnectButton.clicked.connect(lambda: self.network.break_connection())

        self.ui.enableReceivingButton.clicked.connect(lambda: self.network.enable_receiving())

        self.ui.disableReceivingButton.clicked.connect(lambda: self.network.disable_receiving())

        self.ui.sendButton.clicked.connect(lambda: self.network.start_send_file_thread(self.file_to_transfer.file_path,
                                                                                       self.file_to_transfer.file_name,
                                                                                       self.file_to_transfer.file_size))

        self.ui.receiveButton.clicked.connect(lambda: self.network.start_receive_file_thread())

        self.ui.rejectButton.clicked.connect(lambda: self.network.reject_file())

        # Connect the signals
        self.network.receive_progress_bar_signal.connect(self.update_receive_progress_bar)
        self.network.send_progress_bar_signal.connect(self.update_send_progress_bar)
        self.network.spinner_signal.connect(self.toggle_spinner)
        self.network.outbound_connection_indicator_signal.connect(self.update_outbound_connection_indicators)
        self.network.inbound_connection_indicator_signal.connect(self.update_inbound_connection_indicators)
        self.network.receiving_allowed_indicator_signal.connect(self.update_receiving_allowed_label)
        self.network.file_sent_indicator_signal.connect(self.update_file_sent_label)
        self.network.file_ready_to_receive_signal.connect(self.update_receive_label)
        self.network.sent_file_has_been_downloaded_signal.connect(self.update_sent_file_has_been_downloaded_label)
        self.network.reset_file_indicators_signal.connect(self.reset_file_indicators)
        self.network.exception_signal.connect(self.show_exception_message)

        # Set up spinner
        self.spinner = self.get_spinner_gif()
        self.ui.spinnerLabel.setMovie(self.spinner)
        self.toggle_spinner(False)

        # Display warning if upnp is not enabled on network
        if not self.network.upnp_enabled:
            self.show_exception_message("WARNING: UPNP is not enabled on network. Manual port mapping must be done "
                                        "for receiving to work.")

    # Used when program is about to exit
    def exit(self):
        self.network.exit()

    # Gets the program icon (has to be done this way because of pyinstaller)
    def get_program_icon(self):
        root = os.path.dirname(__file__)
        program_icon = os.path.join(root, "icon.ico")
        return program_icon

    # Gets the spinner gif (has to be done this way because of pyinstaller)
    def get_spinner_gif(self):
        root = os.path.dirname(__file__)
        spinner_gif = os.path.join(root, "spinner.gif")
        return QMovie(spinner_gif)

    # Toggles the spinner
    def toggle_spinner(self, status):
        if status:
            self.spinner.start()
            self.ui.spinnerLabel.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        else:
            self.spinner.stop()
            self.ui.spinnerLabel.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Ignored)

    # Shows an exception message for a specific amount of time
    def show_exception_message(self, message):
        self.ui.statusbar.showMessage(message, 10000)

    # Updates the host port to chosen value
    def update_host_port(self):
        new_port = self.ui.portSpinBox.value()
        self.network.host_port = new_port

    # Updates the receiving label to the relevant status
    def update_receiving_allowed_label(self, status):
        if status:
            self.ui.receivingLabel.setText("Receiving enabled")
            self.ui.receivingLabel.setStyleSheet(self.green_color_formatted)
        else:
            self.ui.receivingLabel.setText("Receiving disabled")
            self.ui.receivingLabel.setStyleSheet(self.red_color_formatted)

    # Updates the outbound connection indicators to the relevant status
    def update_outbound_connection_indicators(self, status):
        if status:
            self.ui.outboundConnectionLabel.setText(f"Outbound connection to: {self.network.outbound_peer_public_ip}")
            self.ui.outboundConnectionLabel.setStyleSheet(self.green_color_formatted)
            self.set_ip_line_edit_border_color(self.green_color)
        elif not status and not self.network.outbound_connection:
            self.ui.outboundConnectionLabel.setText("No outbound connection")
            self.ui.outboundConnectionLabel.setStyleSheet(self.red_color_formatted)
            self.set_ip_line_edit_border_color(self.red_color)

    # Updates the inbound connection indicators to the relevant status
    def update_inbound_connection_indicators(self, status):
        if status:
            self.ui.inboundConnectionLabel.setText(f"Inbound connection from: {self.network.inbound_peer_public_ip}")
            self.ui.inboundConnectionLabel.setStyleSheet(self.green_color_formatted)
        elif not status:
            self.ui.inboundConnectionLabel.setText("No inbound connection")
            self.ui.inboundConnectionLabel.setStyleSheet(self.red_color_formatted)

    # Sets the border color of the ip line edit
    def set_ip_line_edit_border_color(self, color):
        style_sheet = ("QLineEdit {{border: 2px solid #ccc; border-radius: 5px; "
                       "padding: 5px; color: white; border-color: {}}}".format(color))
        self.ui.ipLine.setStyleSheet(style_sheet)

    # Updates the file sent label
    def update_file_sent_label(self, status):
        if status:
            self.ui.fileSentLabel.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        else:
            self.ui.fileSentLabel.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Ignored)

    def update_receive_label(self, status):
        if status:
            self.ui.readyToReceiveLabel.setText(f"Ready to receive: {self.network.file_to_be_received_name}")
            self.update_receive_progress_bar(0)
        else:
            self.ui.readyToReceiveLabel.setText(f"Ready to receive:")

    # Updates the sent file has been downloaded label
    def update_sent_file_has_been_downloaded_label(self, status, file_name):
        if status:
            self.ui.receiverDownloadedFileLabel.setText(f"The sent file \"{file_name}\" has been downloaded by the "
                                                    f"receiver.")
        else:
            self.ui.receiverDownloadedFileLabel.setText(f"The sent file \"{file_name}\" was REJECTED by the "
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
        try:
            initial_dir = os.getcwd()

            # Returns a tuple where first element is path
            file_path_unformatted = QFileDialog.getOpenFileName(self.window, "Choose file", initial_dir)
            file_path = file_path_unformatted[0]

            # Set metadata for the file
            if file_path:
                self.reset_file_indicators()
                file_name = os.path.basename(file_path)
                file_size = os.path.getsize(file_path)

                self.file_to_transfer = FileMetadata(file_path, file_name, file_size)

                self.ui.chosenFileLabel.setText(f"Chosen file: {file_name}")
        except Exception as e:
            self.show_exception_message(f"An error occurred: {e}")
            logging.warning(f"An error occurred: {e}")

    # Confirms the IP of the client
    def confirm_client_ip(self):
        try:
            user_input = self.ui.ipLine.text()
            ip, port = user_input.split(":")  # Extract the IP and port
            port = int(port)
            self.network.start_request_connection_thread(ip, port)
        except Exception as e:
            self.show_exception_message("IP-address input is invalid.")
            logging.warning(f"An error occurred: {e}")