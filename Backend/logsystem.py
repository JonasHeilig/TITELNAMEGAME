import os
import logging
from datetime import datetime


class LogSystem:
    def __init__(self):
        self.log_folder = os.path.join(os.getcwd(), "serverlogs")
        if not os.path.exists(self.log_folder):
            os.makedirs(self.log_folder)

        log_filename = datetime.now().strftime("%Y-%m-%d-%H-%M-%S.log")
        self.log_file_path = os.path.join(self.log_folder, log_filename)

        self.logger = logging.getLogger("ServerLogger")
        self.logger.setLevel(logging.DEBUG)

        file_handler = logging.FileHandler(self.log_file_path)
        file_handler.setLevel(logging.DEBUG)

        formatter = logging.Formatter("[%(asctime)s] %(levelname)s - %(message)s", "%d-%m-%Y %H:%M:%S")
        file_handler.setFormatter(formatter)

        self.logger.addHandler(file_handler)

    def initialize(self, description):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.logger.info(f" Log initialized at {timestamp} ")
        self.logger.info(f" Description: {description} ")

    def log_info(self, message):
        self.logger.info(f"{message}")

    def log_warning(self, message):
        self.logger.warning(f"{message}")

    def log_error(self, message):
        self.logger.error(f"{message}")
