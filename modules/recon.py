from bacnet.service import BACnetService, SegAck
from bacnet.object import BACnetObject, BACnetObjectList, BACnetObjectIdentifier, create_app_object, app_object_type_enum
from bacnet.enum import vendor_id,property_identifier_enum, error_class,error_code, get_enum_by_property_and_object, object_types_emo
from bacnet.sequence import  get_ctxt_by_property_and_object
from bacnet.bitstring import bitstring_by_property, service_supported_bs, object_types_bs
from bacnet.datalink import *
from utils import *
import time
import struct

from decoded_value import read_value, Enumerated

from decoded_value import value_by_type

property_ids = {
    "Vendor" :  b'\x79',
    "Vendor_id" :  b'\x78',
    "Object" :  b'\x4d',
    "Object_id" :  b'\x4b',
    "Descrition" :  b'\x1c',
    "Model" :  b'\x46',
    "Firmware" :  b'\x2c',
    "Application Version" :  b'\x0c',
    "Location" :  b'\x3a',
}

def read_property(dl: BACnet_Data_Link, obj : BACnetObject,property_id: bytes, timeout: float = 2.0):
    """Send a read property request and wait for a response from the BACnet device.

    :param dl: The BACnet data link object used for communication.
    :param obj: The BACnet object for which the property is being read.
    :param property_id: The property ID to be read from the object.
    :param timeout: The timeout for waiting for a response in seconds (default is 2.0).
    :return: The response bytes if a response is received, None if no response is received within the timeout.
    """
    read_property = BACnetService(0,12, [
        obj,
        BACnetObject(1,1,len(property_id), property_id)
    ])
    return remove_bvlc_npdu_header( dl.send_and_get(read_property) )



def get_property_or_default(dl: BACnet_Data_Link, obj : BACnetObjectIdentifier,property_id: bytes, default):
    """
    Reads a property of a BACnet object and returns its value.
    If the property is not present, returns the specified default value.

    Parameters:
        dl (BACnet_Data_Link): The BACnet data link to communicate with.
        obj (BACnetObjectIdentifier): The BACnet object identifier.
        property_id (bytes): The property identifier in byte format.
        default: The default value to return if the property is missing.

    Returns:
        Decoded property value or the default value.
    """
    r = read_property(dl, obj ,property_id)
    p = default
    if r[0] !=0x50:
        p,_ = read_value(r[11:])
        p=p.decoded_val
    return p



def read_device_property(dl: BACnet_Data_Link ,property_id: bytes, timeout: float = 2.0):
    """Read a specific property from the device by sending a read property request.

    :param dl: The BACnet data link object used for communication.
    :param property_id: The property ID to be read from the device.
    :param timeout: The timeout for waiting for a response in seconds (default is 2.0).
    :return: The response bytes if a response is received, None if no response is received within the timeout.
    """
    device =BACnetObject(0,1,4, b"\x02\x3f\xff\xff")

    return read_property(dl, device, property_id, timeout)

def infos(dl: BACnet_Data_Link):
    """Fetch and display information about the device properties.
    Iterates over predefined property IDs, reads their values, and displays the results.

    :param dl: The BACnet data link object used for communication.
    """
    for k in property_ids :
        resp = read_device_property(dl,property_ids[k])
        if resp is None:
            fail(f"Connection Failed")
            return
        if resp[0]== 0x60:
            fail(f" Reject : {reject_reason[resp[2]]}")
            return
        if resp[0]==0x50:
            fail(f"\t{k:<20} : {error_code[resp[6]]}")
        else :
            resp
            val,_ = read_value(resp[11:])
            val= val.decoded_val

        if k == "Vendor_id":
            val = vendor_id.get(val, f"Unknown Vendor {val}")

        result(f"\t{k:<20} : {val}")


def get_property_list(dl : BACnet_Data_Link, obj : BACnetObject):
    """Fetches the list of properties for a given BACnet object.

    This function sends a read property request to fetch a list of properties associated with
    the provided object and returns the list of property IDs as raw byte values.

    :param dl: The BACnet data link object used for communication.
    :param obj: The BACnet object for which the property list is being fetched.
    :return: A list of property IDs as byte values if successful, None if an error occurs.
    """
    resp = read_property(dl,obj,b'\x01\x73')
    if check_response_print(resp)!= "Ok":
        return
    val,_ = read_value(resp[11:])
    #add object type, name, identifier
    return [b'\x4b',b'\x4d',b'\x4f'] + [ v.raw_val for v in val.decoded_val]

def get_property_list_str(dl : BACnet_Data_Link, obj : BACnetObject):
    """Fetches the list of properties for a given BACnet object.

    :param dl: The BACnet data link object used for communication.
    :param obj: The BACnet object for which the property list is being fetched.
    :return: A list of property name if successful, None if an error occurs.
    """
    lst = get_property_list(dl, obj)
    if not lst : return
    return [property_identifier_enum.get(int.from_bytes(id,'big'),f"{int.from_bytes(id,'big')}") for id in lst ]


def read_and_decode_property(dl, id_byte, obj , obj_type):
    id = int.from_bytes(id_byte, 'big')
    property_identifier = property_identifier_enum.get(id,f"Vendor_Specific_Property_{id}")

    resp = read_property(dl,obj, id_byte )
    if resp is None:
        fail(f"Connection Failed")
        return None,None,None
    #property is not present
    if resp[0] ==0x50:
        fail(f"\t{ property_identifier_enum[id]:<35} : {error_code[resp[12]]}")
        return None,None,None
    if resp[0]==0x71:
        fail(f"\t{ property_identifier_enum[id]:<35} : Missing")
        return None,None,None
    

    val,_ = read_value(resp[(9+len(id_byte)):],
                            get_ctxt_by_property_and_object(property_identifier, obj_type ),
                            get_enum_by_property_and_object(property_identifier,obj_type),
                            bitstring_by_property.get(property_identifier,{}))

    #convert octet string to ip or mac for convenience
    if id in [400,401,405,406,409,411,414,418]:
        val.to_IP()
    if id in [152, 423]:
        val.to_MAC()
    
    return resp, val, property_identifier


def read_all_property(dl: BACnet_Data_Link, obj : BACnetObject, obj_type : str):
    """Reads all properties of a given BACnet object and prints the results.

    This function first fetches the property list of the object, then iterates through
    the list and reads each property. It prints the value or status for each property.

    :param dl: The BACnet data link object used for communication.
    :param obj: The BACnet object for which the properties are being read.
    :param obj_type: The type of object, which may influence how properties are handled.
    :return: None. It prints the results for each property read.
    """

    #get property-list
    property_list = get_property_list(dl,obj)
    if not property_list:
        return None

    for id_byte in property_list :
        raw, val, property_identifier = read_and_decode_property(dl,id_byte, obj, obj_type)
        if not raw:
            continue        

        #property is empty
        if len(val.decoded_val)==0:
            result(f"\t{ property_identifier:<35} : ,")
            continue

        #print as a alone value
        if len(val.decoded_val) ==1 and val.decoded_val[0].typ not in ["List"]:
            val = val.decoded_val[0]
            if val.typ == "BitString":
                bs_str = str_bistring(val,f"\t{ property_identifier:<35} : ").replace("\n","\n\t")
                result(f"{bs_str}")
                continue

            result(f"\t{ property_identifier:<35} : {val.decoded_val} ({val.typ})")
            continue
        #print as a list
        list_str = str_list(val.decoded_val,f"\t{ property_identifier:<35} : ").replace("\n","\n\t")
        result(f"{list_str}")



def device_properties(dl: BACnet_Data_Link):
    """Reads and prints all properties of the BACnet device."""

    read_all_property(dl,  BACnetObject(0,1,4, b"\x02\x3f\xff\xff"), "device")

def object_properties(dl: BACnet_Data_Link, obj_type : str, instance : int):
    """Reads and prints all properties of a specific BACnet object.

    :param dl: The BACnet data link used for communication.
    :param obj_type: The type of the BACnet object
    :param instance: The instance number of the object.
    """
    obj = BACnetObjectIdentifier(obj_type, instance).get_object(0,1)
    if obj is None: return None
    read_all_property(dl,  obj, obj_type)


def get_service_supported(dl: BACnet_Data_Link):
    """Reads the list of supported BACnet services."""
    resp = read_device_property(dl, b'\x61')
    if check_response_print(resp) != "Ok" : return
    val,_ = read_value(resp[11:])
    return [service_supported_bs[i] for i,b in enumerate(val.decoded_val) if b=='1']

def service_supported(dl: BACnet_Data_Link):
    """Reads and prints the list of supported BACnet services."""
    service_supported_list = get_service_supported(dl)
    for s in service_supported_list:
            result(f"\t- {s}")


def list_object_types_supported(dl : BACnet_Data_Link):
    resp = read_device_property(dl, b'\x60')
    if check_response_print(resp) != "Ok" : return None
    val,_ = read_value(resp[11:])
    lst=[]
    for (i,b) in enumerate(val.decoded_val):
        if b == '1':
            lst.append(object_types_bs[i])
    return lst


def object_types_supported(dl: BACnet_Data_Link):
    """Retrieves and prints the list of BACnet object types supported by the device."""

    object_list= list_object_types_supported(dl)
    result(f"Supported Object Types : ")
    for obj in object_list:
        result(f"\t- { obj }")


def list_objects(dl: BACnet_Data_Link):
    """
    Retrieves a list of BACnet objects from the device.

    Parameters:
        dl (BACnet_Data_Link): The BACnet data link instance.

    Returns:
        list: A list of BACnet object identifiers.
    """
    resp = read_device_property(dl, b'\x4c')
    if check_response_print(resp) != "Ok" : return

    resp = resp[10:]
    val,resp = read_value(resp)
    return [v.decoded_val for v in val.decoded_val]


def list_objects_info(dl: BACnet_Data_Link):
    """
    Retrieves and prints information about all BACnet objects.

    Parameters:
        dl (BACnet_Data_Link): The BACnet data link instance.
    """
    object_list = list_objects(dl)
    #resp = read_device_property(dl, b'\x4c')

    result(f" Objects List : ")
    
    for obj in object_list:

        name = get_property_or_default(dl,obj.get_object(0,1),b'\x4d',"")
        desc = get_property_or_default(dl,obj.get_object(0,1),b'\x1c',"")
        value = get_property_or_default(dl,obj.get_object(0,1),b'\x55',"")

        emoji = object_types_emo.get(obj.obj_type,"🏗️ ")
        result(f"\t{emoji} {str(obj):<25} name : {str(name):<50} description : {desc:<100} value : {value}")


def event_info(dl: BACnet_Data_Link):
    """
    Retrieves and prints  event summary

    Parameters:
        dl (BACnet_Data_Link): The BACnet data link instance.
        service_id (int): The BACnet service identifier for events or alarms.
        title (str): The title to display in output.
    """
    resp = remove_bvlc_npdu_header(dl.send_and_get(BACnetService(0,29,[])))
    if check_response_print(resp) != "Ok" : return

    val,buf = read_value(resp[3:])
    #print as a list
    list_str = str_list(val.decoded_val,f"\t{'Events':<35} : ").replace("\n","\n\t")
    result(f"{list_str}")
    val,_ = read_value(buf)
    result(f"\t{'more Events':<35} : {'FALSE' if val.decoded_val==0 else 'TRUE'}")



def find_devices(dl: BACnet_Data_Link):
    whoIs = BACnetService(1,8, []) 
    resps = dl.broadcast_and_get(whoIs)
    if type(dl) is BACnet_Ip:
        for resp,addr in resps:

            if resp[6] == 0x03:
                continue


            connect = ""

            if resp[5]== 0x08:
                network = int.from_bytes(resp[6:8],"big")
                vmac_len= resp[8]
                vmac = resp[9:9+vmac_len].hex()
                connect= f"BBMD Network : {network} vmac : {vmac}"
                if vmac_len == 6:
                     connect+= f"({decode_ip_port(resp[9:15])})"
                resp=resp[11+vmac_len:]
            else:
                resp=resp[8:]
                connect = "Direct"
            device, r =read_value(resp)
            max_apdu, r =read_value(r)
            seg, r =read_value(r)
            vendor, r =read_value(r)
            vendor = vendor_id.get(vendor.decoded_val, f"Unknown Vendor {vendor.decoded_val}")

            result(f"\t{addr[0]}:{addr[1]} : {device.decoded_val} ({vendor}) Connection :   {connect}")
    else :
        for r in resps:
            resp = r["payload"]
            addr = r["orig_Vaddr"]

            resp=resp[4:]
            device, r =read_value(resp)
            max_apdu, r =read_value(r)
            seg, r =read_value(r)
            vendor, r =read_value(r)
            vendor = vendor_id.get(vendor.decoded_val, f"Unknown Vendor {vendor.decoded_val}")
            print(addr)
            result(f"\t VMAC : {addr.hex()} is {device.decoded_val} ({vendor})")
