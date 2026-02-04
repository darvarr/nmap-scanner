import ipaddress


def is_valid_ip(ip_addr: str) -> bool:
    try:
        ipaddress.ip_address(ip_addr)
        return True
    except ValueError:
        return False

def is_valid_cidr(subnet: str) -> bool:
    try:
        ipaddress.ip_network(subnet, strict=False)
        return True
    except ValueError:
        return False

def validator(targets: list) -> bool:
    for target in targets:
        if not is_valid_ip(target) and not is_valid_cidr(target):
            print("Target must be a valid IP or a valid CIDR")
            return False

    return True