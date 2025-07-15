
from bacnet.service import BACnetService
from bacnet.object import *
from bacnet.enum import reject_reason, vendor_id,property_identifier_enum, enum_by_property,error_class, error_code, reinitialize_device_enum
from bacnet.datalink import *
from modules.recon import read_property
from decoded_value import read_value
from bacnet.datalink import *
from utils import *
import socket
import time
import struct
import ipaddress

def read_atomic_sector(dl: BACnet_Data_Link,obj : BACnetObject, offset : int, length: bytes):
    """
    Reads a specific sector of an atomic file from a BACnet device.
    
    Args:
        dl (BACnet_Data_Link): The BACnet data link for communication.
        obj (BACnetObject): The BACnet object representing the file.
        offset (int): The offset from where to start reading.
        length (bytes): The number of bytes to read.

    Returns:
        Response from the BACnet device after attempting to read the sector.
    """
    if offset == 0:
        l=1
        offset = b"\x00"
    else :
        l = (offset.bit_length() + 7) // 8  # Minimum bytes needed
        offset =  offset.to_bytes(l, byteorder="big")
    read_apdu = BACnetService(0,6 ,[
        obj,
        BACnetObjectList(0, [
            BACnetObject(3,0,l, offset),
            BACnetObject(2,0,2, length), 
        ])
    ])
    return remove_bvlc_npdu_header(dl.send_and_get(read_apdu))

def read_atomic(dl: BACnet_Data_Link, instance : int,file_name : str = "",):
    """
    Reads an atomic file from a BACnet device and saves it locally in the dump folder.
    
    Args:
        dl (BACnet_Data_Link): The BACnet data link for communication.
        instance (int): The BACnet file instance number.
        file_name (str, optional): The name of the file to save. Defaults will be save with name on device.

    Returns:
        None
    """

    #Create objects
    typ = (10 << 6).to_bytes(2,'big')
    inst = instance.to_bytes(3,'big')
    obj_val = typ[:1] + (typ[1]+inst[0]).to_bytes(1,'big') + inst[1:]
    obj = BACnetObject(0,1,4, obj_val)

    #Get object length
    resp = read_property(dl,obj, b'\x2a' )
    if check_response_print(resp) != "Ok":return
    val,_ = read_value(resp[11:])
    length = val.decoded_val
    #Get file name
    if file_name == "":
        resp = read_property(dl, obj, b'\x4d' )
        if check_response_print(resp) != "Ok":return
        val,_, = read_value(resp[11:])
        file_name= val.decoded_val

    Eof = False
    buffer = b''
    offset=0
    size =1446

    #read file

    obj = BACnetObject(12,0,4, obj_val)

    while offset<length:
        size_to_read = min(size, length-offset)

        resp = read_atomic_sector(dl , obj ,offset, size_to_read.to_bytes(2, "big"))

        if check_response_print(resp) != "Ok":return
            
        EoF,resp = read_value(resp[3:])
        start,resp = read_value(resp[1:])
        b,_  = read_value(resp)
        buffer+=b.decoded_val
        offset+=size

    try :
        with open("dump/"+file_name, 'wb') as file:
            file.write(buffer)
    except FileNotFoundError:
        fail(f"Error: The file '{file_name}' was not found.")
    except PermissionError:
        success(f"Error: Permission denied while trying to open '{file_name}'.")

def write_property_index(dl: BACnet_Data_Link, obj, property_id: bytes, value : BACnetObject, priority : int, index : int):
    """
    Writes a property value to a BACnet object at a specific index.

    Args:
        dl (BACnet_Data_Link): The BACnet data link layer used for communication.
        obj: The BACnet object to write to.
        property_id (bytes): The property ID to be modified.
        value (BACnetObject): The new value to write.
        priority (int): The priority level for writing the value.
        index (int): The index within the property array.

    Returns:
        Response from the BACnet device.
    """
    write_property = BACnetService(0,15, [
        obj,
        BACnetObject(1,1,len(property_id), property_id),
        BACnetObject(2,1,1, index.to_bytes(1,"little")),
        BACnetObjectList(3,[ value ]),
        BACnetObject(4,1,1, priority.to_bytes(1,"little")),
    ])
    return dl.send_and_get(write_property)

def write_property(dl: BACnet_Data_Link, obj, property_id: bytes, value : BACnetObject, priority : int):
    """
    Writes a property value to a BACnet object.

    Args:
        dl (BACnet_Data_Link): The BACnet data link layer used for communication.
        obj: The BACnet object to write to.
        property_id (bytes): The property ID to be modified.
        value (BACnetObject): The new value to write.
        priority (int): The priority level for writing the value.

    Returns:
        Response from the BACnet device.
    """
    write_property = BACnetService(0,15, [
        obj,
        BACnetObject(1,1,len(property_id), property_id),
        BACnetObjectList(3,[value]),
        BACnetObject(4,1,1, priority.to_bytes(1,"little")),
    ])
    return remove_bvlc_npdu_header(dl.send_and_get(write_property))


def write_property_object_value(dl: BACnet_Data_Link, obj_type : str, instance : int, properti: str, val_type : str, value : str, priority : int):
    """
    Writes a value to a specified property of a BACnet object.

    Args:
        dl (BACnet_Data_Link): The BACnet data link layer used for communication.
        obj_type (str): The BACnet object type (e.g., 'analogValue', 'binaryOutput').
        instance (int): The instance number of the object.
        property_name (str): The name or ID of the property to be modified.
        val_type (str): The type of value being written (e.g., 'int', 'float', 'string').
        value (str): The actual value to be written.
        priority (int): The priority level for writing the value.

    Returns:
        None
    """
    obj = BACnetObjectIdentifier(obj_type, instance).get_object(0,1)
    if obj is None: return None


    property_id = int(properti).to_bytes(4,"big") if properti.isdigit() else get_property(properti)
    
    if property_id is None:
        return 

    value = create_app_object(val_type,value)
    if value is None:
        return

    resp =  write_property(dl,obj,property_id,value, priority)
    if check_response_print(resp) != "Ok":return

    success(f"Property was updated")

def write_property_object_value_index(dl: BACnet_Data_Link, obj_type : str, instance : int, properti: str, val_type : str, value : str, priority : int, index : int):
    """
    Writes a value to a specified indexed property of a BACnet object.

    Args:
        dl (BACnet_Data_Link): The BACnet data link layer used for communication.
        obj_type (str): The BACnet object type (e.g., 'analogValue', 'binaryOutput').
        instance (int): The instance number of the object.
        property_name (str): The name or ID of the property to be modified.
        val_type (str): The type of value being written (e.g., 'int', 'float', 'string').
        value (str): The actual value to be written.
        priority (int): The priority level for writing the value.
        index (int): The index within the property array.

    Returns:
        None
    """
    obj = BACnetObjectIdentifier(obj_type, instance).get_object(0,1)
    if obj is None: return None

    property_id = int(properti).to_bytes(4,"big") if properti.isdigit() else get_property(properti)
    
    if property_id is None:
        return 

    value = create_app_object(val_type,value)
    if value is None: return None

    resp =  write_property_index(dl,obj,property_id,value, priority, index)
    if check_response_print(resp) != "Ok":return
    success(f"Property was updated")


def set_time(dl : BACnet_Data_Link, date: str, time : str):
        """
        Sets the time and date on a BACnet device.

        Args:
            dl (BACnet_Data_Link): The BACnet data link layer used for communication.
            date (str): The date to set (format day.month.year.DoW).
            time (str): The time to set (format hour:mmin:sec).

        Returns:
            None
        """
        date_byte = create_app_object("Date", date)
        time_byte = create_app_object("Time", time)
        if date_byte is None or time_byte is None :return

        service = BACnetService(1,9, [date_byte,time_byte])
        resp = remove_bvlc_npdu_header(dl.send_and_get(service))


def create(dl: BACnet_Data_Link,obj_type :str, instance : int,):
    """
    Creates a BACnet object.

    Args:
        dl (BACnet_Data_Link): The BACnet data link layer used for communication.
        obj_type (str): The type of BACnet object to create.
        instance (int): The instance number of the object.

    Returns:
        None
    """
    obj = BACnetObjectIdentifier(obj_type, instance).get_object(1,1)
    if obj is None: return None

    read_apdu = BACnetService(0,10 ,[
        BACnetObjectList(0,[
            obj
        ]),
    ])

    resp = remove_bvlc_npdu_header(dl.send_and_get(read_apdu))
    if check_response_print(resp) != "Ok":return

    success(f"Object created")
    return

def delete(dl: BACnet_Data_Link,obj_type :str, instance : int):
    """
    Deletes a BACnet object.

    Args:
        dl (BACnet_Data_Link): The BACnet data link layer used for communication.
        obj_type (str): The type of BACnet object to delete.
        instance (int): The instance number of the object.

    Returns:
        None
    """
    obj = BACnetObjectIdentifier(obj_type, instance).get_object(12)
    if obj is None: return None

    resp = remove_bvlc_npdu_header(dl.send_and_get(BACnetService(0,11 ,[obj])))

    if check_response_print(resp) != "Ok":return

    success(f"Object deleted")
    return

def reinit(dl: BACnet_Data_Link, state : str, password : str):
    """
    Reinitializes a BACnet device with a specified state.

    Args:
        dl (BACnet_Data_Link): The BACnet data link layer used for communication.
        state (str): The reinitialization state (must be valid in BACnet enum).
        password (str): The password required for reinitialization.

    Returns:
        None
    """
    state_value = {v:k for k,v in reinitialize_device_enum.items()}.get(state,None)
    if state_value is None:
        fail(f"Unknown reinitialize state : Shoulb be in {list(reinitialize_device_enum.values())}")
        return        
    if password:
        reinit_apdu =  BACnetService(0,20, [ BACnetObject(0,1,1, state_value.to_bytes(1,"little")),  BACnetObject(1,1,5, (len(password)+1).to_bytes(1,'little')+ b'\x00' + password.encode())])
    else:
        reinit_apdu =  BACnetService(0,20, [ BACnetObject(0,1,1, state_value.to_bytes(1,"little"))])

    resp = remove_bvlc_npdu_header(dl.send_and_get(reinit_apdu))

    if check_response_print(resp) != "Ok":return

    success(f"Device reinitialized")
    return

def device_communication(dl: BACnet_Data_Link, enable : bool, password : str):
    """
    Enables or disables device communication on a BACnet device.

    Args:
        dl (BACnet_Data_Link): The BACnet data link layer used for communication.
        enable (bool): True to enable, False to disable.
        password (str): The password required to change the device communication state.

    Returns:
        None
    """
    if password :    
        apdu = BACnetService(0, 17, [
            BACnetObject(1,1,1, b'\x00' if enable else b'\x01'),
            BACnetObject(2,1,5,(len(password)+1).to_bytes(1,'little')+ b'\x00' + password.encode())
        ])
    else:
        apdu = BACnetService(0, 17, [
            BACnetObject(1,1,1, b'\x00' if enable else b'\x01'),
        ])
    
    resp = remove_bvlc_npdu_header(dl.send_and_get(apdu))
    if check_response(resp) not in ["Ok","Error"]:return

    if check_response_print(resp) == "Error":
        if resp[4]==4 and resp[6]== 26:return

        if not enable:
            info(f"\tCould not disable the device totally (normally deprecated)")
            info(f"\tTrying to disable only initiation...")
            

            if password :    
                apdu = BACnetService(0, 17, [
                    BACnetObject(1,1,1, b'\x02'),
                    BACnetObject(2,1,5,(len(password)+1).to_bytes(1,'little')+ b'\x00' + password.encode())
                ])
            else:
                apdu = BACnetService(0, 17, [
                    BACnetObject(1,1,1, b'\x02'),
                ])
            
            resp = remove_bvlc_npdu_header(dl.send_and_get(apdu))
            if check_response_print(resp) != "Ok": return
            success(f"\tDevice Initiation  was Disabled")

        return
    
    success("\tDevice Enabled" if enable else "\tDevice Disabled")

def connect(dl: BACnet_Data_Link, vmac : str):
    
    if type(dl) is BACnet_Ip:
        try:
            ipaddress.ip_address(vmac)
            dl.ip=vmac
        except:
            new_vmac= bytes.fromhex(vmac)

            dl.destination= new_vmac
    else:
        new_vmac= bytes.fromhex(vmac)
        if len(new_vmac) not in [0,6]:
            fail("VMAC should be 6 bytes long")
        else:
            dl.destination= new_vmac
            success(f"Connected to {vmac if vmac else 'default'}")

def set_network_number(dl: BACnet_Data_Link, n : int):
    if type(dl) is BACnet_Ip:
        dl.network_number = n
    else:
        fail("\t command only supported for BACnet/IP")

