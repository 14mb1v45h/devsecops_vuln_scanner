import logging
import os

def setup_logging(log_file="vuln_scanner.log"):
    """Configure logging for the application."""
    logger = logging.getLogger("DevSecOpsVulnScanner")
    logger.setLevel(logging.DEBUG)

    # File handler
    log_path = os.path.join(os.path.dirname(__file__), log_file)
    file_handler = logging.FileHandler(log_path)
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    file_handler.setFormatter(file_formatter)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter("%(name)s - %(levelname)s - %(message)s")
    console_handler.setFormatter(console_formatter)

    # Add handlers
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger
