import logging
import os
from logging.handlers import RotatingFileHandler

LOG_FOLDER = "app_data"
LOG_FILENAME = "app.log"
LOG_FILE_PATH = os.path.join(LOG_FOLDER, LOG_FILENAME)
LOG_MAX_BYTES = 5 * 1024 * 1024 # 5 MB
LOG_BACKUP_COUNT = 3

# Ensure log directory exists
os.makedirs(LOG_FOLDER, exist_ok=True)

def setup_logging(log_level=logging.INFO):
    """Configure the root logger."""
    log_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(name)s - %(message)s'
    )
    
    # Get root logger
    logger = logging.getLogger()
    logger.setLevel(log_level) # Set the base level

    # --- File Handler ---
    # Rotate log files (5MB each, keep 3 backups)
    file_handler = RotatingFileHandler(
        LOG_FILE_PATH, 
        maxBytes=LOG_MAX_BYTES, 
        backupCount=LOG_BACKUP_COUNT,
        encoding='utf-8'
    )
    file_handler.setFormatter(log_formatter)
    file_handler.setLevel(log_level) # Log level for the file

    # --- Console Handler ---
    console_handler = logging.StreamHandler() # Defaults to stderr
    console_handler.setFormatter(log_formatter)
    # Optionally set a different level for console, e.g., only show WARNING and above
    # console_handler.setLevel(logging.WARNING) 
    console_handler.setLevel(log_level) # Log level for console

    # --- Add handlers to the root logger ---
    # Clear existing handlers to avoid duplicates if called multiple times
    if logger.hasHandlers():
        logger.handlers.clear()
        
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    # --- Set level for noisy libraries (optional) ---
    # logging.getLogger("some_noisy_library").setLevel(logging.WARNING)

    # Return the configured root logger (optional, can also use logging.getLogger directly elsewhere)
    return logger

# Example usage (optional, can be removed if logger is imported directly)
# if __name__ == '__main__':
#     logger = setup_logging()
#     logger.debug("This is a debug message.")
#     logger.info("This is an info message.")
#     logger.warning("This is a warning message.")
#     logger.error("This is an error message.")
#     logger.critical("This is a critical message.") 