import os
from dotenv import load_dotenv

load_dotenv()


NMAP_OPTIONS_UDP = os.getenv("NMAP_OPTIONS_UDP", "-sU -Pn -T4 -n --source-port 53")
NMAP_OPTIONS_TCP = os.getenv("NMAP_OPTIONS_TCP", "-sS -Pn -T4 -n --source-port 53")
MIN_RATE = int(os.getenv("MIN_RATE", 0))
MAX_RATE = int(os.getenv("MAX_RATE", 0))
OUTPUT_FOLDER = os.getenv("OUTPUT_FOLDER", "/tmp/nmap_report")
LOG_DIR = os.getenv("LOG_DIR", "/var/log/nmap_scanner")
LOG_PATH = f"{LOG_DIR}/nmap_scanner.log"
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

os.makedirs(OUTPUT_FOLDER, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)