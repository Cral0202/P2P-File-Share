import logging
from gui_controller import GUIController

# Change logging level to CRITICAL for production, WARNING for debug
logging.basicConfig(level=logging.CRITICAL, format="%(asctime)s - %(levelname)s - %(lineno)d - %(message)s")

if __name__ == "__main__":
    gui_controller = GUIController()
    gui_controller.window_setup()
