import sys
from PyQt6 import QtWidgets
from mainGUI import Ui_MainWindow

if __name__ == "__main__":
    # Setup window
    app = QtWidgets.QApplication(sys.argv)

    # Create main window
    window = QtWidgets.QMainWindow()

    # Set up UI
    ui = Ui_MainWindow()
    ui.setupUi(window)

    # Show the window
    window.show()

    sys.exit(app.exec())