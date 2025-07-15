import struct
from bacnet.enum import days_of_week, object_types
from bacnet.object import BACnetObjectIdentifier, app_object_type_enum


class decoded_value:
    """
    Base class for decoded values
    """
    typ="None"
    def __init__(self,val,tag, field=None, enum = {}, bitstring= {}):
        """
        Initialize the DecodedValue object.

        Args:
            val (bytes): Raw value.
            tag (int): Tag associated with the value.
            field (str, optional): Field name.
            enum (dict, optional): Enumeration mapping.
            bitstring (dict, optional): Bitstring mapping.
        """
        self.raw_val=val
        self.tag=tag
        self.field = field
        self.enum = enum
        self.bitstring = bitstring
        self.decoded_val=self.decode()
    def decode(self):
        """Decodes the raw value. Should be overridden by subclasses."""
        return self.raw_val

    def __str__(self):
        """String representation of the decoded value."""
        return f"{self.typ} : {self.decoded_val}"


class Null(decoded_value):
    typ="Null"
    def decode(self):
        return "Null"

class Bool(decoded_value):
    typ="Bool"
    def decode(self):
        if len(self.raw_val)==0:
            return (self.tag&1 == 1)
        else:
            return self.raw_val ==1

class UnsignedInt(decoded_value):
    typ="UnsignedInt"
    def decode(self):
        return int.from_bytes(self.raw_val,'big')

class SignedInt(decoded_value):
    typ="SignedInt"
    def decode(self):
        return int.from_bytes(self.raw_val,'big', signed=True)

class Real(decoded_value):
    typ="Real"
    def decode(self):
        return struct.unpack(">f", self.raw_val)[0]

class Double(decoded_value):
    typ="Double"
    def decode(self):
        return struct.unpack(">d", self.raw_val)[0]

class OctetString(decoded_value):
    typ="OctetString"
    def decode(self):
        return self.raw_val

    def to_IP(self):
        self.decoded_val = ".".join(f"{byte}" for byte in self.decoded_val)
    def to_MAC(self):
        self.decoded_val = ":".join(f"{byte:02X}" for byte in self.decoded_val)

class CharString(decoded_value):
    typ="CharString"
    def decode(self):
        return self.raw_val[1:].decode()

class Bit(decoded_value):
    def decode(self):
        self.typ= self.raw_val
        return ""

class BitStringValue(decoded_value):
    typ="BitString"
    def decode(self):
        return''.join(format(byte, '08b') for byte in self.raw_val[1:])  



class BitString(decoded_value):
    typ="BitStringList"
    def decode(self):
        v = BitStringValue(self.raw_val,self.tag)
        val = v.decoded_val
        if not self.bitstring:
            return val
        bs_list = [v]
        for (i,b) in enumerate(val):
            bit= self.bitstring.get(i,None)
            if bit: bs_list.append(Bit(b,b"",bit))            
        return  bs_list

class BitString(decoded_value):
    typ="BitString"
    def decode(self):
        return''.join(format(byte, '08b') for byte in self.raw_val[1:])  

        
class Enumerated(decoded_value):
    typ="Enumerated"
    def decode(self):
        return self.enum.get(int.from_bytes(self.raw_val,'big'),self.raw_val)
    def set_enum(self, enum :dict):
        self.enum=enum
        self.decoded_val=self.decode

class Date(decoded_value):
    typ = "Date"
    def decode(self):
        date = [i for i in self.raw_val]
        for i in range(0,4):
            if self.raw_val[i] == 0xff :
                date[i]= "Any"
            elif i==0:
                date[i]= self.raw_val[i]+1900
            elif i == 3:
                date[i]=days_of_week.get(date[i],date[i])
        return f"{date[2]}.{date[1]}.{date[0]} DoW : {date[3]}"

class Time(decoded_value):
    typ = "Time"
    def decode(self):
        val = ["Any" if i==0xff else i for i in self.raw_val]
        return f"{val[0]}:{val[1]}:{val[2]}" 

class Identifier(decoded_value):
    typ = "Identifier"
    def decode(self):
        instance = self.raw_val[1:]
        instance=(instance[0]& 63).to_bytes(1,'little') +instance[1:]
        object_type = (self.raw_val[0]<<2) + (self.raw_val[1]>>6)
        return BACnetObjectIdentifier(object_types.get(object_type,object_type), int.from_bytes(instance,'big'))

class ContextType(decoded_value):
    typ="ContextType"
    def decode(self):
        return self.raw_val

class List(decoded_value):
    typ="List"
    def decode(self):
        return self.raw_val
    def to_IP(self):
        """Converts applicable values within the list to IP addresses."""
        [v.to_IP()  for v  in self.decoded_val if type(v) in [OctetString,List]]
    def to_MAC(self):
        """Converts applicable values within the list to MAC addresses."""
        [v.to_MAC()  for v  in self.decoded_val if type(v) in [OctetString,List]]


type_by_id = {
    "Null" : Null,
    "Bool" : Bool,
    "UnsignedInt" : UnsignedInt,
    "SignedInt" : SignedInt,
    "Real" : Real,
    "Double" : Double,
    "OctetString" : OctetString,
    "CharString" : CharString,
    "BitString" : BitString,
    "Enumerated" : Enumerated,
    "Date" : Date,
    "Time" : Time,
    "Identifier" : Identifier,
    "ContextType" : ContextType
}

def value_by_type(tag : bytes,val :bytes, app_type, field : str, enum, bitstring):
    """Returns an instance of the appropriate value class."""
    typ =  type_by_id[app_type]
    return typ(val,tag,field, enum, bitstring)


def read_value(resp, ctx = ({},()), enum ={}, bitstring={}):
    """
    Reads and decodes a single BACnet value from the response buffer.

    Args:
        resp (bytes): The BACnet response buffer.
        ctx (tuple): A tuple containing:
            - type_ctx (dict): Context type mappings.
            - field_ctx (tuple): Field context mappings.
        enum (dict, optional): Enumeration mapping for the value.
        bitstring (dict, optional): Bitstring mapping for the value.

    Returns:
        tuple:
            - DecodedValue: An instance of the appropriate decoded value class.
            - bytes: The remaining buffer after extracting the value.
    """
    # Extract tag info
    length = 0
    tag = resp[0]
    length_tag = resp[0] & 7
    app_type =  resp[0]>>4
    context = tag>>3 &1

    #context
    type_ctx, field_ctx = ctx 

    #when it is an application boolean length is 0
    if app_type== 1 and context==0: length_tag=0

    # Deal it as a list of value
    if length_tag==6:

        #Check if new context
        passed_ctx = ctx
        if context==1 and app_type in type_ctx:
            e = type_ctx[app_type]
            ctxt = e.ctx_type
            f = e.field
            if type(ctxt) == tuple:
                passed_ctx = ctxt
            if e.enum is not None:
                enum = e.enum
            if e.bitstring is not None: bitstring = e.bitstring
        val,buf = read_list(resp,passed_ctx, enum, bitstring)

        # Add field
        if field_ctx and val.typ=="List":
            for (v,f) in zip(val.decoded_val,field_ctx):
                v.field=f.field
                if f.enum is not None :
                    v.set_enum(f.enum)
                if f.bitstring is not None:
                    v.bitstring=f.bitstring

        return val,buf
    #check for length
    elif length_tag==5:
        length=resp[1]
        resp=resp[2:]
        if length == 0xfe:
            length = int.from_bytes(resp[:2], 'big')
            resp=resp[2:]
    else:
        length=length_tag
        resp=resp[1:]
    
    value = resp[:length]
    buffer = resp[length:]

    field_name=None

    typ = "ContextType"
    if context==0:
        typ = app_object_type_enum[app_type]
    else:
        e = type_ctx.get(app_type,None)
        if e is not None:
            typ = e.ctx_type
            field_name = e.field
            if e.enum is not None:
                    enum = e.enum
            if e.bitstring is not None:
                bitstring = e.bitstring
    value =  value_by_type(tag, value, typ, field_name, enum, bitstring)
    return value, buffer

def read_list(resp,ctx, enum, bitstring):
    """
    Reads and decodes a list of BACnet values from the response buffer.

    Args:
        resp (bytes): The BACnet response buffer.
        ctx (tuple): A tuple containing:
            - type_ctx (dict): Context type mappings.
            - field_ctx (tuple): Field context mappings.
        enum (dict): Enumeration mapping for values in the list.
        bitstring (dict): Bitstring mapping for values in the list.

    Returns:
        tuple:
            - List: A `List` object containing decoded values.
            - bytes: The remaining buffer after extracting the list.
    """
    buffer =resp[1:]
    lst = []
    while buffer[0]&7 != 7:
        val,buffer= read_value(buffer,ctx, enum, bitstring)
        lst.append( val)

    return List(lst,resp[0], None),buffer[1:]