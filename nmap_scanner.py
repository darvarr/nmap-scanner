import argparse

from configs import OUTPUT_FOLDER
from src.services.nmap import ScanService, NmapExporter
from utils import validator
from src.services.logger import logger

parser = argparse.ArgumentParser(prog="Nmap Scanner",
                                 description="Automated nmap scanner using python",
                                 epilog="Developed by Tiger Team")

parser.add_argument("-t", "--target")
parser.add_argument("-e", "--exclude")
parser.add_argument("-p", "--output_path")

args = parser.parse_args()

if not args.target:
    print("Missing arguments: TARGET")
    print("Usage: ./nmap_scanner 192.168.1.1,192.168.2.1")
    exit(1)
targets = args.target
parsed_targets = targets.split(",")
if not validator(parsed_targets):
    print("Bad format for argument TARGET")
    exit(1)

parsed_exclude = None
exclude = args.exclude
if exclude:
    parsed_exclude = exclude.split(",")
    if not validator(parsed_exclude):
        print("Bad format for argument EXCLUDE")
        exit(1)

output_path = args.output_path if args.output_path else OUTPUT_FOLDER

sanitized_targets = targets.replace("/", "_")
output_tcp_path = f"{output_path}/{sanitized_targets}_tcp"
output_udp_path = f"{output_path}/{sanitized_targets}_udp"

scan_service = ScanService()
nmap_exporter = NmapExporter()

logger.info("**********************")
alive_hosts = scan_service.launch_discovery(parsed_targets)
logger.info(f"Alive hosts: {alive_hosts}")
logger.info("**********************")
logger.info("Starting TCP port scanning...")
results_tcp = scan_service.launch_nmap(alive_hosts, protocol="tcp", exclude=parsed_exclude, single_ip_scan=False,
                                       output_path=f"{output_tcp_path}.txt")
logger.info("TCP port scanning ended!")
logger.info("**********************")
nmap_exporter.export_results(results_tcp, f"{output_tcp_path}.csv", "csv")
logger.info("**********************")
logger.info("Starting UDP port scanning...")
results_csv_udp = scan_service.launch_nmap(alive_hosts, protocol="udp", exclude=parsed_exclude, single_ip_scan=False,
                                           output_path=f"{output_udp_path}.txt")
logger.info("UDP port scanning ended!")
logger.info("**********************")
nmap_exporter.export_results(results_csv_udp, f"{output_udp_path}.csv", "csv")
