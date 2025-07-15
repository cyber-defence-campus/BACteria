from bacnet.service import BACnetService
from bacnet.object import BACnetObject, BACnetObjectList
import socket
from colorama import Fore, Style
from bacnet.datalink import *
from utils import *


def check_ws(ip : str, port : int, valid_port : list):
    """Check for a valid BACnet/SC service on a given IP and port.

    :param ip: The IP address of the BACnet device.
    :param port: The port number to check.
    :param valid_port: List to append valid BACnet/SC services.
    """
    dl = BACnet_SC(ip,port,"cert/self-signed-key.pem","cert/self-signed-cert.pem")
    resp = dl.connect_ws()

    if resp == "Bad_certificate":
        info(f"\t{port} : BACnet/SC service  but a valid certificate is needed")
    elif resp == "OK":
        success(f"\t{port} : Found BACnet/SC service accepting self-signed certificate foundrunning")
        valid_port.append(dl)
    else:
        result(f"\t{port} : No BACnet service running")
    


def scan_port(ip:str):
    """Scan for BACnet IP services on common BACnet ports.

    :param ip: The IP address to scan.
    :return: A list of valid BACnet/IP service instances.
    """
    info(f"No port were given. Start scanning common BACnet port ... ")

    valid_port =[]
    for port in range(47808,47824):
        read_property = BACnetService(0,12, [
            BACnetObject(0,1,4, b"\x02\x3f\xff\xff"),
            BACnetObject(1,1,1, b'\x4b')])
        resp = BACnet_Ip(ip,port,0.5).send_and_get(read_property)
        
        if resp is None:
            check_ws(ip, port, valid_port)
        else :
            success(f"\t{port} : Found BACnet IP service running")
            valid_port.append(BACnet_Ip(ip,port))
    return valid_port
    
def choose_port(ip:str, valid_port : list):
    """Prompt the user to select a BACnet service from the list of valid ports.

    :param ip: The IP address of the BACnet device.
    :param valid_port: List of valid BACnet service instances.
    :return: The selected BACnet service instance.
    """
    if not valid_port:return

    if len(valid_port)==1:
        info(f"Running BACteria against {ip}:{valid_port[0].port}")
        return valid_port[0]

    result(f" Multiple BACnet instance found : ")
    for i, num in enumerate(valid_port, start=1):
        result(f"\t({i}) {num.port}")

    # Get user selection
    while True:
        try:
            choice = int(input(f"{Fore.YELLOW}Select a port: {Style.RESET_ALL}"))
            if 1 <= choice <= len(valid_port):
                info(f"Running BACteria against {ip}:{valid_port[choice-1].port}")

                return valid_port[choice - 1]
            else:
                fail(f"Invalid choice. Please enter a number from the list.")
        except ValueError:
            fail(f"Invalid input. Please enter a valid number.")