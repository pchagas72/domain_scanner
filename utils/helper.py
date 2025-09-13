import os
import re
from dotenv import dotenv_values


class Helper:
    def __init__(self):
        self.color_green = '\033[92m'
        self.color_yellow = '\033[93m'
        self.color_blue = '\033[94m'
        self.color_red = '\033[91m'
        self.color_reset_colors = '\033[0m'
        self.color_bold = '\033[1m'
        self.config = {}
        self.output_path = None

    def log(self, message: str, color: str = ''):
        """Prints to console and writes to an output file if specified."""
        log_message = f'{color}{message}{self.color_reset_colors}'
        print(log_message)

        if self.output_path:
            clean_message = re.sub(r'\033\[[0-9;]*m', '', message)
            try:
                with open(self.output_path, 'a', encoding='utf-8') as f:
                    f.write(clean_message + '\n')
            except IOError as e:
                print(
                    f'{self.color_red}[-] Critical Error: Could not write to output file {self.output_path}: {e}{self.color_reset_colors}'
                )

    def read_config_env(self, config_path: str):
        """Loads configuration from a .env file."""
        if os.path.exists(config_path):
            self.log(
                f'[*] Loading configuration from: {config_path}',
                self.color_yellow,
            )
            self.config = dotenv_values(config_path)
        else:
            self.log(
                f'[-] Config file not found at: {config_path}. Using command-line args and defaults.',
                self.color_red,
            )


def log_info(message, helper):
    helper.log(message, helper.color_blue)


def log_error(message, helper):
    helper.log(message, helper.color_red)


def log_warning(message, helper):
    helper.log(message, helper.color_yellow)


def log_success(message, helper):
    helper.log(message, helper.color_green)
