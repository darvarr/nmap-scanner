import logging

from configs import LOG_PATH, LOG_LEVEL

LOG_LEVELS = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}

logger = logging.getLogger("nmap_scanner")
log_level = LOG_LEVELS.get(LOG_LEVEL, logging.INFO)
logger.setLevel(log_level)
logging.getLogger().setLevel(log_level)
formatter = logging.Formatter(
    "%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s"
)

file_handler = logging.FileHandler(LOG_PATH, encoding="utf-8")
file_handler.setFormatter(formatter)
file_handler.setLevel(log_level)

if logger.hasHandlers():
    logger.handlers.clear()

logger.addHandler(file_handler)