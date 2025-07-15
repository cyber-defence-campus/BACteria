from bacnet.object import BACnetObject, BACnetObjectList
from inputs import Device_Identifier, Password_char
import copy





class BACnetService:
  """Represents a BACnet service"""
  apdu_type : int
  service : int
  objects : list

  def __init__(self, apdu_type:int, service : int, objects : list):
    """
    Initializes a BACnetService instance.
    
    :param apdu_type: The APDU type (Application Protocol Data Unit type)
    :param service: The service identifier
    :param objects: A list of objects associated with the service, expected to have a `get_bytes` method
    """
    self.apdu_type = apdu_type
    self. service = service
    self.objects = objects


  def get_bytes(self)-> bytes:
    """
    Converts the BACnetService instance into its byte representation.

    :return: Byte representation of the service.
    """
    header = None
    if self.apdu_type ==1 :
      header : bytes = (self.apdu_type << 4 ).to_bytes(1,'little') + self.service.to_bytes(1,'little')
    elif self.apdu_type == 0:
      header : bytes = ((self.apdu_type << 4) +2).to_bytes(1,'little') +b"\x75\x01" + self.service.to_bytes(1,'little')
    else:
      raise ValueError("Unsupported APDU type")
    if isinstance(self.objects, bytes):
          return header + self.objects

    return header + b''.join([o.get_bytes() for o in self.objects])

  def copy(self):
    """
    Creates a deep copy of the BACnetService instance.

    :return: A new instance of BACnetService with the same data.
    """
    return copy.deepcopy(self)

  def __str__(self):
    """
    Returns a string representation of the BACnetService instance.
    
    :return: A formatted string describing the service and its objects.
    """
    service_name = get_service_name(self.apdu_type, self.service)
    string = ""
    for o in self.objects:
      string += "\n"+str(o)
 
    return f"{service_name} :"+string.replace("\n","\n    ")

def get_service_name(apdu: int, service: int) -> str:
    """
    Retrieves the service name based on the APDU type and service identifier.

    :param apdu: APDU type (1 for unconfirmed, 0 for confirmed)
    :param service: Service identifier
    :return: The name of the service, or 'Unknown service' if not found.
    """
    l = unconfirmed_service if apdu == 1 else confirmed_service
    for k, v in l.items():
        if v.service == service:
            return k
    return f"Unknown service {service}"



class SegAck:
    """
    Represents a Segment Acknowledgment (SegAck) message.
    """
    def __init__(self, seg: int):
        """
        Initializes a SegAck instance.

        :param seg: The segment number to acknowledge.
        """
        self.seg = seg

    def get_bytes(self) -> bytes:
        """
        Converts the SegAck instance into its byte representation.

        :return: A byte sequence representing the SegAck message.
        """
        return b'\x40\x01' + self.seg.to_bytes(1, 'big') + b'\x04'


#List containing example of different unconfirmed service services
unconfirmed_service = {
  "i-am" : BACnetService(1,0, [BACnetObject(12, 0, 4, Device_Identifier), BACnetObject(2,0,2, b'\x05\x00'), BACnetObject(9, 0, 1, b'\x03' ), BACnetObject(2, 0, 2, b'\x01\x00')]),
  "i-have" : BACnetService(1,1, [BACnetObject(12, 0, 4, Device_Identifier), BACnetObject(12, 0, 4, b'\x02\x00\x00\x7b'), BACnetObject(7,0,5, b'\x05\x00name')]),
  "unconfirmed-cov-notification" : BACnetService(1,2, [BACnetObject(0,1,1, b'\x01'), BACnetObject(1,1,4, Device_Identifier), BACnetObject(2,1,4, b'\x00\xc0\x00\x04') , BACnetObject(3,1,1, b'\x05'), BACnetObjectList(4, [BACnetObject(0,1,1,b'\x55'), BACnetObjectList(2, [BACnetObject(4,0,4,b'\x42\xc8\x00\x00')])])  ]),
  "unconfirmed-event-notification" : BACnetService(1,3, [BACnetObject(0,1,2,b'\x30\x39'), BACnetObject(1,1,4, Device_Identifier ), BACnetObject(2, 1, 4, b'\x00\xc0\x00\x10'),BACnetObjectList(3, [ BACnetObjectList(2, [BACnetObject(10,0,4, b'\x6d\x0a\x1c\x03'), BACnetObject(11,0,4, b'\x0e\x01\x2e\x00')]) ]), BACnetObject(4,1,1, b'\x03'), BACnetObject(5,1,1, b'\x00'), BACnetObject(6,1,1, b'\x01'), BACnetObject(8,1,1, b'\x00'), BACnetObject(9,1,1, b'\x00'), BACnetObject(10,1,1, b'\x00'), BACnetObject(11,1,1, b'\x02'), BACnetObjectList(12, [BACnetObjectList(1, [ BACnetObjectList(0,[BACnetObject(1,1,1,b'\x01')]), BACnetObject(1,1,2, b'\x04\x80')])]) ]),
  "unconfirmed-private-transfer" : BACnetService(1,4,[BACnetObject(2,0,2, b'\x00\x0a'), BACnetObject(2,0,4, b'\x00\x00\x00\x07')]) ,
  "unconfirmed-text-message" : BACnetService(1,5,[BACnetObject(0, 1, 4, Device_Identifier), BACnetObject(2,1,1,b'\x00'), BACnetObject(3,1,5, b'\x08\x00message') ]),
  "time-synchronization" : BACnetService(1,6, [BACnetObject(10,0,4, b'\x6d\x0a\x1c\x03'), BACnetObject(11,0,4, b'\x0e\x01\x2e\x00')]),
  "who-has" : BACnetService(1,7, [ BACnetObject(0,1,4, b'\x00\x00\x00\x00'), BACnetObject(1,1,4, b'\x00\x3f\xff\xff') ]) ,
  "who-is" : BACnetService(1,8, [ BACnetObject(0,1,4, b'\x00\x00\x00\x00'), BACnetObject(1,1,4, b'\x00\x3f\xff\xff') ]) ,
  "utc-time-synchronization" : BACnetService(1,9, [BACnetObject(10,0,4, b'\x6d\x0a\x1c\x03'), BACnetObject(11,0,4, b'\x0e\x01\x2e\x00')]),
  "write-group" : BACnetService(1,10,[]), #TODO
  "unconfirmed-cov-notification-multiple" : BACnetService(1,11,[]), #TODO
  "unconfirmed-audit-notificatio" : BACnetService(1,12,[]), #TODO
  "who-Am-I" :  BACnetService(1,13, [BACnetObject(2,0,2, b'\x00\xaa'), BACnetObject(7,0,5, b'\x05\x00name'),BACnetObject(7,0,5, b'\x07\x00serial')]),
  "you-Are" :   BACnetService(1,14, [BACnetObject(2,0,2, b'\x00\xaa'), BACnetObject(7,0,5, b'\x05\x00name'),BACnetObject(7,0,5, b'\x07\x00serial'), BACnetObject(12, 0, 4, Device_Identifier)])
}

#List containing example of different confirmed service services
confirmed_service = {
  "acknowledge-alarm" :  BACnetService(0,0, [ BACnetObject(0,1,2, b"\x00\x01"), BACnetObject(1,1,4, b"\x00\x00\x00\x01"), BACnetObject(2,1,2, b"\x00\x01"), BACnetObject(10,0,4, b'\x6d\x0a\x1c\x03'), BACnetObject(11,0,4, b'\x0e\x01\x2e\x00'), BACnetObject(7,0,5, b'\x04\x00src'), BACnetObject(10,0,4, b'\x6d\x0a\x1c\x03'), BACnetObject(11,0,4, b'\x0e\x01\x2e\x00')]),
  "confirmed-cov-notification"  : BACnetService(0,1, [BACnetObject(0,1,1, b'\x01'), BACnetObject(1,1,4, Device_Identifier), BACnetObject(2,1,4, b'\x00\xc0\x00\x04') , BACnetObject(3,1,1, b'\x05'), BACnetObjectList(4, [BACnetObject(0,1,1,b'\x55'), BACnetObjectList(2, [BACnetObject(4,0,4,b'\x42\xc8\x00\x00')])])  ]),
  "confirmed-event-notification" : BACnetService(0,2, [BACnetObject(0,1,2,b'\x30\x39'), BACnetObject(1,1,4, Device_Identifier ), BACnetObject(2, 1, 4, b'\x00\xc0\x00\x10'),BACnetObjectList(3, [ BACnetObjectList(2, [BACnetObject(10,0,4, b'\x6d\x0a\x1c\x03'), BACnetObject(11,0,4, b'\x0e\x01\x2e\x00')]) ]), BACnetObject(4,1,1, b'\x03'), BACnetObject(5,1,1, b'\x00'), BACnetObject(6,1,1, b'\x01'), BACnetObject(8,1,1, b'\x00'), BACnetObject(9,1,1, b'\x00'), BACnetObject(10,1,1, b'\x00'), BACnetObject(11,1,1, b'\x02'), BACnetObjectList(12, [BACnetObjectList(1, [ BACnetObjectList(0,[BACnetObject(1,1,1,b'\x01')]), BACnetObject(1,1,2, b'\x04\x80')])]) ]),
  "get-enrollment-summary" : BACnetService(0,4,[]), #TODO (Mainly deprecated)
  "subscribe-cov" :BACnetService(0,5,[BACnetObject(0,1,1, b'\x01'), BACnetObject(1,1,4, b'\x00\xc0\x00\x04'),BACnetObject(2,1,0,b""), BACnetObject(3,1,1,b'\x00')]),
  "atomic-read-file" : BACnetService(0,6, [ BACnetObject(12,0,4, b'\x02\x80\x00\x01'), BACnetObjectList(0, [ BACnetObject(3,0,2, b'\x00\x00'), BACnetObject(2,0,2, b'\x05\x05'), ])  ]),
  "atomic-write-file" : BACnetService(0,7, [ BACnetObject(12,0,4, b'\x02\x80\x00\x01'), BACnetObjectList(0, [ BACnetObject(3,0,2, b'\x00\x00'), BACnetObject(6,0,5, b'\x07content'), ])  ]),
  "add-list-element"  : BACnetService(0,8, [ BACnetObject(0,1,4, b"\x01\x00\x00\x01"), BACnetObject(1,1,1, b'\x55'),BACnetObject(2,1,1, b'\x01')]),#TODO,
  "remove-list-element"  : BACnetService(0,9, [ BACnetObject(0,1,4, b"\x01\x00\x00\x01"), BACnetObject(1,1,1, b'\x55'),BACnetObject(2,1,1, b'\x01')]),#TODO,
  "create-object" : BACnetService(0,10 ,[BACnetObjectList(0,[BACnetObject(1,1,4, b"\x01\x00\x00\x01")])]),
  "delete-object" : BACnetService(0,11, [ BACnetObject(12,0,4, b"\x01\x00\x00\x01")]),
  "read-property" : BACnetService(0,12, [ BACnetObject(0,1,4, b"\x01\x00\x00\x01"), BACnetObject(1,1,1, b'\x55'), BACnetObject(2,1,1, b'\x00') ]),
  "write-property" : BACnetService(0,15, [ BACnetObject(0,1,4, b"\x01\x00\x00\x01"), BACnetObject(1,1,1, b'\x55'), BACnetObject(2,1,1, b'\x00'), BACnetObjectList(3, [BACnetObject(0,0,0)])  ]),
  "device-communication-control" : BACnetService(0, 17, [BACnetObject(0,1,2,b"\x00\x10"),  BACnetObject(1,1,1, b'\x00'), BACnetObject(2,1,5, Password_char) ]),
  "reinitialize-device" :  BACnetService(0,20, [ BACnetObject(0,1,1, b'\x00'),  BACnetObject(1,1,5, Password_char)]),
  "subscribe-cov-property" :  BACnetService(0,28, [ BACnetObject(0,1,1, b'\x12'),  BACnetObject(1,1,4, b'\x00\x00\x00\x0A'), BACnetObject(2,1,1, b'\x01'),BACnetObject(3,1,1, b'\x3c'),BACnetObjectList(4,[BACnetObject(0,1,1, b'\x55')]), BACnetObject(5,1,4, b'\x3f\x80\x00\x00')]),
  }

all_service = {**unconfirmed_service, ** confirmed_service}
