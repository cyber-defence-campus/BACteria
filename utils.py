import socket
import time
from colorama import Fore, Style
from bacnet.enum import property_identifier_enum, reject_reason, error_class, error_code

# =======================
# PRINT FUNCTIONS
# =======================
def success(s:str):
    print(f"{Fore.GREEN}{s}{Style.RESET_ALL}")
def fail(s:str):
    print(f"{Fore.RED}{s}{Style.RESET_ALL}")
def info(s:str):
    print(f"{Fore.YELLOW}{s}{Style.RESET_ALL}")
def result(s:str):
    print(f"{Fore.CYAN}{s}{Style.RESET_ALL}")

# =======================
# BACnet Helper Functions
# =======================

def parse_object_identifier(obj_id : str):
    """
    Parses a BACnet object identifier in the format 'type:instance'.

    Args:
        obj_id (str): The object identifier string.

    Returns:
        tuple: (str, int) -> (object type, instance number) or (None, None) if invalid.
    """
    parts = obj_id.split(":")
    if len(parts) != 2:
        fail("Invalid object Identifier! Expected one ':' separator.")
        return None, None

    typ, instance = parts

    if not typ.isascii():
        fail("Invalid object Identifier!! type must be a string.")
        return None, None

    if not instance.isdigit():
        fail("Invalid format! Instance  must be an int")
        return None, None


    return typ, int(instance)


def get_property(prop : str):
    """
    Converts a property name into its BACnet property ID.

    Args:
        prop (str): The property name.

    Returns:
        bytes: The property ID in byte format or None if invalid.
    """
    prop =  {v:k for k,v in property_identifier_enum.items()}.get(prop,None)
    if prop is None:
        fail(f"Unknown property type")
        return None

    return prop.to_bytes(2,'big') if prop>255 else prop.to_bytes(1,'big')


def check_response(resp):
    """
    Checks the response type from a BACnet message.

    Args:
        resp (bytes): The BACnet response message.

    Returns:
        str: One of ["Connection", "Reject", "Error", "Ok"]
    """
    if resp is None:
        return "Connection"
    if resp[0] == 0x60:
        return "Reject"
    if resp[0] ==0x50:
        return "Error"
    return "Ok"

def check_response_print(resp):
    """
    Checks the BACnet response and prints corresponding messages.
    Args:
        resp (bytes): The BACnet response message.

    Returns:
        str: One of ["Connection", "Reject", "Error", "Ok"]
    """
    if resp is None:
        fail(f"Connection Failed")
        return "Connection"
    if resp[0] == 0x60:
        fail(f" Reject : {reject_reason[resp[2]]}")
        return "Reject"
    if resp[0] ==0x50:
        error_index = 4 if resp[3] == 0x91 else 5
        error_class_str = error_class.get(resp[error_index], "Unknown Class")
        error_code_str = error_code.get(resp[error_index + 2], "Unknown Code")
        fail(f"{error_class_str} Error: {error_code_str}")
        return "Error"
    return "Ok"

# =======================
# STRING FORMATTING
# =======================

def str_bistring(bs, header="", field=""):
    """
    Formats a BACnet BitString value as a human-readable string.

    Args:
        bs: The BitString object.
        header (str, optional): The header description.
        field (str, optional): The field name.

    Returns:
        str: Formatted string representation.
    """
    header = f"{header:<37}{field}"
    bs_str =  f"{header:<{37+len(field)}}{bs.decoded_val} ({bs.typ})\n"
    header = ""

    for (i,b) in enumerate(bs.decoded_val):
        name = bs.bitstring.get(i,None)
        if name :
            bs_str += f"{header:<{37+len(field)}} {b} : {name}\n"
    
    return bs_str.strip()

def str_list(lst, header = "",field=""):
    """
    Formats a BACnet List value as a human-readable string.

    Args:
        lst (list): The list of BACnet values.
        header (str, optional): The header description.
        field (str, optional): The field name.

    Returns:
        str: Formatted string representation.
    """
    if len(lst)==0:
        return f"{header:<37}[]"
    
    header = f"{header:<37}{field}["
    list_str=""

    for i,v in enumerate(lst):
        field_info = f"{v.field} : " if v.field else ""

        if v.typ == "List":
            list_str += str_list(v.decoded_val, header, field_info)
        elif v.typ == "BitString":
            list_str += str_bistring(v, header, field_info)
        else:
            list_str += (f"{header:<{37+len(field)}}{field_info}{v.decoded_val} ({v.typ})")
   
        eol = ("]" if i==len(lst)-1 else ',\n ')
        list_str+=f"{eol}"
        header=""

    return list_str.replace("\n","\n ")

def decode_ip_port(data: bytes) -> str:
    if len(data) != 6:
        raise ValueError("Data must be exactly 6 bytes long")

    ip_bytes = data[:4]
    port_bytes = data[4:]

    ip_str = ".".join(str(b) for b in ip_bytes)
    port = int.from_bytes(port_bytes, byteorder='big')  # use 'little' if needed

    return f"{ip_str}:{port}"

# =======================
# BITSTRING PARSING
# =======================

def parse_bitsring(val, bs):
    """
    Parses a BitString and extracts the named bits.

    Args:
        val (bytes): The bitstring value.
        bs (dict): A dictionary mapping bit positions to names.

    Returns:
        list: A list of tuples (bit name, bit value, None)
    """
    return [(bit, f"{b}", None) for i, b in enumerate(val) if (bit := bs.get(i))]

def remove_bvlc_npdu_header(resp):
    if not resp: return resp

    header_length= 4 # BVLC
    header_length+= 2 #NPUD version+control
    control = resp[5]
    if control == 32:
        header_length+=2 # DNet
        dlen=resp[header_length]
        header_length+=dlen+1
    if control ==8:
        header_length+=2 # SNet
        slen=resp[header_length]
        header_length+=slen+1
    if (control & (1<<5) ) != 0:
        header_length+=1 #HopCount
    return resp[header_length:]