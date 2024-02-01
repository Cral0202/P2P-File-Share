import sys
import requests
from PyQt6 import QtWidgets
from mainGUI import Ui_MainWindow


class Main:
    def __init__(self):
        self.window = None
        self.ui = None
        self.app = None
        self.clipboard = None

        self.user_public_ip = None

    # Sets up the main window
    def window_setup(self):
        self.app = QtWidgets.QApplication(sys.argv)

        self.window = QtWidgets.QMainWindow()

        self.ui = Ui_MainWindow()
        self.ui.setupUi(self.window)

        self.setup_window_widgets()

        self.window.show()
        sys.exit(self.app.exec())

    # Sets up the widgets for the main window
    def setup_window_widgets(self):
        # Set up the clipboard for use
        self.clipboard = QtWidgets.QApplication.clipboard()

        self.ui.ipLabel.setText(f"Your IP: {self.user_public_ip}")
        self.ui.copyButton.clicked.connect(self.copy_user_id_to_clipboard)

    # Gets the public ip of the user
    def get_user_public_ip(self):
        try:
            # Use a public API to get the external IP address
            response = requests.get("https://api64.ipify.org?format=json")
            self.user_public_ip = response.json()["ip"]
            return self.user_public_ip
        except requests.RequestException as e:
            return None

    def copy_user_id_to_clipboard(self):
        self.clipboard.setText(self.user_public_ip)

if __name__ == "__main__":
    main = Main()
    main.get_user_public_ip()
    main.window_setup()
