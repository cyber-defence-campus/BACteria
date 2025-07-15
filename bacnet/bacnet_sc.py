from bacnet.enum import error_class, error_code

# Predefined BVLC messages
connect_request = (
    b'\x06'  # Byte - function_bvlc
    b'\x00'  # Byte - control flags
    b'\x12\x34'  # 2 Bytes - Message ID
    b'\x00\x11\x22\x33\x44\x55'  # 6 Bytes - VMAC
    b'\x0a\x0b\x0c\x0d\x0a\x0b\x0c\x0d\x0a\x0b\x0c\x0d\x0a\x0b\x0c\x0d'  # 16 Bytes - UUID
    b'\x05\xdc'  # Max BVLC length
    b'\x01\xe0'  # Max NPDU length
)

disconnect_request = (
    b'\x08'  # Byte - function_bvlc
    b'\x00'  # Byte - control flags
    b'\x12\x34'  # 2 Bytes - Message ID
)

encapsulated_NPDU_header = (
    b'\x01'  # Byte - function bvlc
    b'\x00'  # Byte - control flags
    b'\x12\x34'  # 2 Bytes - Message ID
    b'\x01'  # Byte - version_bacnet
    b'\x04'  # Byte - control_bacnet
)

# BVLC function mappings
BVLC_BACNetSC_function = {
    0x00: "BVLC-Results",
    0x01: "Encapsulated-NPUD",
    0x02: "Address-Resolution",
    0x03: "Address-Resolution-Ack",
    0x04: "Advertisement",
    0x05: "Advertisement-Solicitation",
    0x06: "Connect-Request",
    0x07: "Connect-Accept",
    0x08: "Disconnect-Request",
    0x09: "Disconnect-Ack",
    0x0A: "Heartbeat-Request",
    0x0B: "Heartbeat-Ack",
}




def decode_connect_accept(msg: bytes) -> dict:
    """Decodes a connect-accept message."""
    return {
        "VMAC": msg[:6],
        "UUID": msg[6:22],
        "Max_BVLC": int.from_bytes(msg[22:24], "big"),
        "Max_NPDU": int.from_bytes(msg[24:26], "big"),
    }


def decode_bvlc_result(msg: bytes) -> dict:
    """Decodes a BVLC result message."""
    result_code = msg[1]
    payload = {
        "BVLC_Function": BVLC_BACNetSC_function.get(msg[0], "Unknown"),
        "Result Code": "ACK" if result_code == 0 else "NAK"
    }
    if result_code == 0:
        return payload
    
    payload.update({
        "Error_Header_Marker": msg[2],
        "Error_Class": error_class.get(int.from_bytes(msg[3:5], "big"), msg[3:5]),
        "Error_Code": error_code.get(int.from_bytes(msg[5:7], "big"), msg[5:7]),
        "Error_Details": msg[7:]
    })
    return payload

def decode_advertisement(msg: bytes) -> dict:
    """Decodes an advertisement message."""
    connection_status = {0: "No hub connection", 1: "Connected to primary hub", 2: "Connected to failover hub"}
    return {
        "Hub_Connection_Status": connection_status.get(msg[0], "Unknown"),
        "Accept_Direct_Connection": bool(msg[1]),
        "Max_BVLC": int.from_bytes(msg[2:4], "big"),
        "Max_NPDU": int.from_bytes(msg[4:6], "big")
    }

def decode_address_resolution_ack(msg: bytes) -> str:
    """Decodes an address resolution acknowledgment."""
    return msg.decode("utf-8")

def decode_encapsulated_npdu(msg: bytes) -> bytes:
    """Decodes an encapsulated NPDU message (returns raw bytes)."""
    return msg


decode_payload_by_function = {
    0 : decode_bvlc_result,
    1 : decode_encapsulated_npdu,
    3 : decode_address_resolution_ack,
    4 : decode_advertisement,
    7 : decode_connect_accept,
}


def decode_received_message(msg: bytes) -> dict:
    """Decodes a received BVLC message."""
    message = {}
    function = msg[0]
    message["function"] = BVLC_BACNetSC_function.get(function, "Unknown")
    
    data_options_flag = msg[1] & 1
    dest_options_flag = msg[1] & 2
    dest_Vaddr_flag = msg[1] & 4
    src_Vaddr_flag = msg[1] & 8
    
    message.update({
        "flags": msg[1],
        "Msg_ID": msg[2:4]
    })
    
    msg = msg[4:]
    if src_Vaddr_flag:
        message["orig_Vaddr"] = msg[:6]
        msg = msg[6:]
    if dest_Vaddr_flag:
        message["dest_Vaddr"] = msg[:6]
        msg = msg[6:]
    if dest_options_flag:
        print("Destination options processing not implemented Yet.")
    if data_options_flag:
        message["data_option_flag"] = msg[0]
        msg = msg[1:]
    
    message["payload"] = decode_payload_by_function.get(function, lambda x: x)(msg)
    return message
