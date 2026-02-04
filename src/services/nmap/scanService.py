import time
from typing import Tuple
import nmap
from masscan import PortScanner
import json

from configs import NMAP_OPTIONS_UDP, NMAP_OPTIONS_TCP, MIN_RATE, MAX_RATE, NMAP_OPTIONS_DISCOVERY, \
    NMAP_OPTIONS_DISCOVERY_ICMP
from src.services.logger import logger


class ScanService:

    def __init__(self, nmap_options_udp: str = NMAP_OPTIONS_UDP, nmap_options_tcp: str = NMAP_OPTIONS_TCP,
                 min_rate: int = MIN_RATE, max_rate: int = MAX_RATE, discovery_options: str = NMAP_OPTIONS_DISCOVERY,
                 discovery_options_icmp: str = NMAP_OPTIONS_DISCOVERY_ICMP):
        self.masscan_scanner = PortScanner()
        self.nmap_scanner = nmap.PortScanner()
        self.nmap_options_udp = nmap_options_udp
        self.nmap_options_tcp = nmap_options_tcp
        self.min_rate = min_rate
        self.max_rate = max_rate
        self.discovery_options = discovery_options
        self.discovery_options_icmp = discovery_options_icmp

    def launch_discovery(self, targets: list) -> list:
        discovery_target = " ".join(targets)
        try:
            logger.debug(f"Starting TCP/UDP discovery on {discovery_target}")
            self.nmap_scanner.scan(hosts=discovery_target, arguments=self.discovery_options)
            alive_hosts = set(self.nmap_scanner.all_hosts())
            logger.debug(f"Starting ICMP discovery on {discovery_target}")
            self.nmap_scanner.scan(hosts=discovery_target, arguments=self.discovery_options_icmp)
            alive_hosts |= set(self.nmap_scanner.all_hosts())
            logger.debug(f"Found the following alive hosts: {alive_hosts}")
            return list(alive_hosts)
        except Exception as e:
            logger.error(f"[launch_discovery] Error during discovery on {discovery_target}: {e}")
            return list()

    def launch_masscan(self, targets: list, protocol: str = "tcp") -> Tuple[list, str]:
        masscan_ports = "U:1-65535" if "udp" in protocol else "1-65535"
        masscan_target = ",".join(targets)
        try:
            self.masscan_scanner.scan(masscan_target, ports=masscan_ports, arguments=f'--max-rate {self.max_rate}')
            results = json.loads(self.masscan_scanner.scan_result).get("scan")
            alive_ip = set()
            port_list = set()
            if results:
                for ip, result in results.items():
                    for port_elem in result:
                        if port_elem and "open" in port_elem["status"]:
                            port_list.add(port_elem["port"])
                            alive_ip.add(ip)
                return list(alive_ip), ",".join(map(str, port_list))
        except Exception as e:
            logger.error(f"[launch_masscan] Error while scanning {masscan_target}: {e}")
        return list(), ""

    def launch_nmap(self, targets: list, ports: str = None, protocol: str = "tcp",
                    single_ip_scan: bool = True, exclude: list = None,
                    output_path: str = None, output_format: str = "text") -> PortScanner:
        nmap_options = self.__arguments_generator(ports=ports, protocol=protocol, exclude=exclude,
                                                  output_path=output_path, output_format=output_format)
        logger.debug(f"[launch_nmap] Arguments generated: {nmap_options}")
        if not single_ip_scan:
            try:
                nmap_target = " ".join(targets)
                logger.debug(f"[launch_nmap] Starting mass ip scanning on {nmap_target}")
                self.nmap_scanner.scan(arguments=nmap_options, hosts=nmap_target)
            except Exception as e:
                logger.error(f"[launch_nmap] Error while scanning {targets}: {e}")
        else:
            combined_results = dict()
            for target in targets:
                try:
                    start = time.time()
                    logger.info(f"Scanning host: {target}")
                    self.nmap_scanner.scan(arguments=nmap_options, hosts=target)
                    for host in self.nmap_scanner:
                        if host in combined_results:
                            combined_results[host].update(self.nmap_scanner[host])
                        else:
                            combined_results[host] = self.nmap_scanner[host]
                    logger.info(f"[launch_nmap] Nmap ended on host {target}, it took {time.time() - start}s")
                except Exception as e:
                    logger.error(f"[launch_nmap] Error while scanning {target}: {e}")
                    continue
        logger.debug(f"[launch_nmap] Nmap ended on {targets}")
        return self.nmap_scanner

    def __arguments_generator(self, ports: str, protocol: str, exclude: list,
                              output_path: str = None, output_format: str = None) -> str:
        nmap_options = f"{self.nmap_options_tcp}" if protocol == "tcp" else f"{self.nmap_options_udp}"
        if exclude:
            exclude_set = set(exclude)
            exclude_str = ",".join(exclude_set)
            nmap_options += f" --exclude {exclude_str}"
        if not ports:
            nmap_options += f" -p-"
        else:
            ports_arg = f" -p U:{ports}" if protocol == "udp" else f" -p {ports}"
            nmap_options += ports_arg
        if self.min_rate != 0 and protocol == "udp":
            nmap_options += f" --min-rate {self.min_rate}"
        if self.max_rate != 0 and protocol == "udp":
            nmap_options += f" --max-rate {self.max_rate}"
        if output_format and output_path:
            if "text" in output_format:
                nmap_options += f" -oN {output_path}"
        return nmap_options
