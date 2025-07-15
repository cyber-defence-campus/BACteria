import random
import struct
from bacnet.enum import object_types
from utils import fail
from bacnet.enum import days_of_week

app_object_type_enum = {
    0: "Null", 1: "Bool", 2: "UnsignedInt", 3: "SignedInt", 4: "Real",
    5: "Double", 6: "OctetString", 7: "CharString", 8: "BitString",
    9: "Enumerated", 10: "Date", 11: "Time", 12: "Identifier"
}

valid_size_by_object_type ={
    0 : [0,1], 1 : [0], 2 : [1,2,3,4], 3 : [1,2,3,4],
    4 : [4], 5 : [5], 6 : [5], 7 : [5], 8 : [5],
    9 : [1,2], 10: [4], 11: [4], 12: [4]
}

class BACnetObject:
    """ Represents a BACnet object with type, class, length, and value."""
    obj_type  : int
    obj_class : int 
    length    : int
    value     : bytes

    def __init__(self, obj_type: int = 0, obj_class: int = 0, length: int = 0, value: bytes = b''):
        """
        Initializes the BACnetObject with given parameters.

        :param obj_type: The type of the BACnet object.
        :param obj_class: The class of the BACnet object(application or context).
        :param length: The length of the value.
        :param value: The byte value representing the BACnet object.
        """
        self.obj_type = obj_type
        self.obj_class = obj_class
        self.length = length
        self.value = value
    
    def get_bytes(self) -> bytes:
        """Returns the byte representation of the BACnetObject."""
        tag : bytes = ((self.obj_type << 4) + (self.obj_class <<3) + self.length).to_bytes(1,"little")
        return tag + self.value

    def __str__(self):
        """Returns a string representation of the BACnetObject."""
        val = self.value if len(self.value) <20 else self.value[:20]+ b'...'
        obj_type_str = app_object_type_enum.get(self.obj_type) if self.obj_class==0 else "Context"
        return f"{obj_type_str:<15} Length : {self.length:<5} Value : {val} "


def get_random_app_object_valid_struct( obj_type=-1, length = None):
    """Generates a random BACnet object with valid structure."""
    if obj_type==-1:
        obj_type = random.randint(0, 12)
    if length is None:
        length = random.randint(0,5)

    if length == 5 :
        size  = pow(2, random.randint(0,1))
        header = b'' if size==0 else b'\xfe'
        pad = b''
        length2 = pow(2,random.randint(0,7)) << (size-1)*8
        random_bytes = bytes(random.getrandbits(8) for _ in range(length2))
        value = header + length2.to_bytes(size,"little") + pad + random_bytes
    else:
        value = bytes(random.getrandbits(8) for _ in range(length))

    return BACnetObject(obj_type, 0, length, value)
    
def get_random_app_object_valid_size( obj_type=-1):
    """Generates a random BACnet object with correct size."""
    if obj_type==-1:
        obj_type = random.randint(0, 12)
    
    length= random.choice(valid_size_by_object_type.get(obj_type))
    return get_random_app_object_valid_struct(obj_type,length)

def get_random_app_object_incoherent_length(obj_type=-1):
    """Generates a BACnet object with an incoherent length."""
    obj = get_random_app_object_valid_struct(obj_type)
    obj.length = random.randint(0,5)
    return obj

class BACnetObjectList():
    """Represents a list of BACnet objects."""
    opening_tag : int
    objects : list

    def __init__(self, opening_tag : int, objects : list):
        """
        Initializes the BACnetObjectList with the given opening tag and list of objects.
        
        :param opening_tag: The opening tag for the BACnet object list.
        :param objects: A list of BACnet objects.
        """
        self.opening_tag = opening_tag
        self.objects = objects

    def get_bytes(self):
        """Returns the byte representation of the BACnetObjectList."""
        tag_value = (self.opening_tag << 4) + 14
        return tag_value.to_bytes(1,'little') + b''.join([o.get_bytes() for o in self.objects]) + (tag_value+1).to_bytes(1,'little')

    def __str__(self):
        """Returns a string representation of the BACnetObjectList."""
        string = ""
        for o in self.objects:
            string += "\n"+str(o)
 
        return "{"+str(self.opening_tag) +string.replace("\n","\n\t") + "\n}"+str(self.opening_tag)

class BACnetObjectIdentifier():
    """
    Represents a BACnet object identifier.
    """
    def __init__(self, obj_type, instance: int):
        """
        Initializes a BACnetObjectIdentifier.

        :param obj_type: The type of BACnet object (string or integer representation)
        :param instance: The instance number of the object
        """
        self.obj_type = obj_type
        self.instance = instance

    def __str__(self) -> str:
        """
        Returns a string representation of the BACnetObjectIdentifier.
        """
        return f"{self.obj_type}:{self.instance}"

    def get_value(self) -> bytes:
        """
        Returns the byte value of the BACnetObjectIdentifier.

        :return: A bytes representation of the object identifier or None if invalid.
        """
        if isinstance(self.obj_type, int):
            typ = self.obj_type
        elif self.obj_type.isdigit():
            typ = int(self.obj_type)
        else:
            typ = {v: k for k, v in object_types.items()}.get(self.obj_type)
            if typ is None:
                fail(f"\tUnknown object type: {self.obj_type}")
                return 
        
        typ2 = (typ << 6).to_bytes(2, 'big')
        inst = self.instance.to_bytes(3, 'big')

        return typ2[:1] + ((typ2[1] + inst[0]).to_bytes(1, 'big')) + inst[1:]

    def get_object(self, obj_type: int =12, obj_class: int = 0):
        """
        Creates a BACnetObject from the identifier.

        :param obj_type: The type of the BACnet object
        :param obj_class: The class of the BACnet object (default: 0)
        :return: A BACnetObject instance or None if value conversion fails.
        """
        val = self.get_value()
        if val is None:
            return None
        return BACnetObject(obj_type, obj_class, 4, val)
  
def create_Null(val : str):
    """Creates a BACnet Null object."""
    return BACnetObject(0,0,0,b"")

def create_bool(val : str):
    """Creates a BACnet Bool object."""
    if val in ["False","false","F"]:
        return BACnetObject(1,0,0,b"")
    if val in ["True","true", "T"]:
        return BACnetObject(1,0,1,b"")
    else:
        fail(f"Unknown Boolean : Should be in [True, False]")        
        return None

def create_Uint(s : str):
    """Creates a BACnet UnsignedInteger object."""
    try:
        num = int(s)  # Convert string to integer
        byte_length = (num.bit_length() + 7) // 8 or 1  # Calculate needed bytes
        val =  num.to_bytes(byte_length, byteorder="big",signed=False)
        return BACnetObject(2,0,byte_length,val)
    except  :  fail(f"{s} is not avalid number ")        

def create_Sint(s : str):
    """Creates a BACnet SignedInteger object."""
    try:
        num = int(s)  # Convert string to integer
        byte_length = (num.bit_length() + 7) // 8 or 1  # Calculate needed bytes
        val =  num.to_bytes(byte_length, byteorder="big",signed=True)
        return BACnetObject(3,0,byte_length,val)
    except  :  fail(f"{s} is not avalid number ")        

def create_Real(s : str):
    """Creates a BACnet Real object."""

    try:
        num = float(s)
        return BACnetObject(4,0,4,struct.pack("!f", num))
    except  :  fail(f"{s} is not a valid number ")        

def create_Double(s : str):
    """Creates a BACnet Double object."""
    try:
        num = float(s)
        return BACnetObject(5,0,8,struct.pack("!d", num))  
    except  :  fail(f"{s} is not a valid number ")        

def create_OctetString(s : str):
    """Creates a BACnet OctetString object."""
    str_val = (len(s)+1).to_bytes(1,'little')+ b'\x00' + s.encode()
    return BACnetObject(6,0,5, str_val)

def create_CharString(s : str):
    """Creates a BACnet CharString object."""

    str_val = (len(s)+1).to_bytes(1,'little')+ b'\x00' + s.encode()
    return BACnetObject(7,0,5, str_val)

def create_BitString(s :str):
    """Creates a BACnet BitString object."""

    if len(s) % 8 !=0:
        fail(f"{s} is not a valid length ") 
    byte_value = int(s,2).to_bytes(len(s) // 8 , byteorder='big')
    byte_value = len(byte_value).to_bytes(1, 'little') + byte_value
    return BACnetObject(8,0,5, byte_value)

def create_Enumerated(s : str):
    """Creates a BACnet Enumerated object."""
    try:
        num = int(s)  # Convert string to integer
        byte_length = (num.bit_length() + 7) // 8 or 1  # Calculate needed bytes
        val =  num.to_bytes(byte_length, byteorder="big",signed=False)
        return BACnetObject(9,0,byte_length,val)
    except  :  fail(f"{s} is not avalid number ")  

def create_Date(s :str):
    """Creates a BACnet Enumerated object."""
    parts = s.split(".")
    if len(parts) != 4 :
        fail(f"Invalid format for a date should be day.month.year.DoW ")
        return  
    try:
        if int(parts[2]) < 1900:
            fail(f"Year should be between 1900 and 2155 ")
            return
        return BACnetObject(10,0,4,bytes([int(parts[2])-1900, int(parts[1]), int(parts[0]), int(parts[3])]))
    except Exception as e:
        fail(f"Day/Month/DoW value should be between 0 and 255 ")

def create_Time(s :str):
    """Creates a BACnet Time object."""
    parts = s.split(":")
    if len(parts) != 4 :
        fail(f"Invalid format for a time should be hour:min:sec:msec ")
        return
    try:  
        return BACnetObject(11,0,4,bytes([int(parts[0]), int(parts[1]), int(parts[2]), int(parts[3])]))
    except:
        fail(f"Time values should be between 0 and 255 ")

def create_Identifier(s:str):
    """Creates a BACnet Identifier object."""
    parts = s.split(":")
    if len(parts) != 2 :
        fail(f"Invalid format for an Identifier should be objectType:Instance_number ")
        return
    try:
        instance = int(parts[1])
        return BACnetObjectIdentifier(parts[0],instance).get_value(12,0)
    except  :  fail(f"{parts[0]} is not avalid number ") 

def create_app_object(obj_type : str, value : str):
    """Creates a BACnet object with a giveen type from a string"""

    obj_type_int = {v:k for k,v in app_object_type_enum.items()}.get(obj_type,None)
    if obj_type_int is None : 
        fail(f'Unknown Object type "{obj_type}" , Should be in {list(app_object_type_enum.values())}')
        return        
    return  {
        0 : create_Null, 1 : create_bool, 2 : create_Uint, 3 : create_Sint,
        4 : create_Real, 5 : create_Double, 6 : create_OctetString, 7 : create_CharString,
        8 : create_BitString, 9 : create_Enumerated, 10: create_Date, 11: create_Time, 12: create_Identifier
    }.get(obj_type_int, None)(value)
