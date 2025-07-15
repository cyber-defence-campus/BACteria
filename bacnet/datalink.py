
from bacnet.service import BACnetService, SegAck
from bacnet.object import *
from bacnet.bacnet_sc import *
from bacnet.enum import reject_reason
from itertools import islice
from utils import *
import sys
import socket
import ssl
import websockets
import asyncio
import aiofiles
from datetime import datetime, timedelta


class BACnet_Data_Link:
    """Base class for BACnet data link layers."""
    def send_and_get(self, apdu: BACnetService):
        """
        Placeholder method for sending and receiving BACnet messages.
        """
        return None
    def network_info(self):
        """
        Placeholder method for getting all info on the datalink
        """
        return None
    def current_target_info(self):
        """
        Placeholder method for printing info on the current target
        """
        return None



bvlc_header = (
    #Request -
        #Block - bacnet_virtual_link_control
        b'\x81'  #Byte - type_bvlc
        b'\x0a'  #Byte - function_bvlc
        b'\x00\x18'  #Word - length_bvlc

        #Block - bacnet_npdu
        b'\x01'  #Byte - version_bacnet
        b'\x04'  #Byte - control_bacnet
)



broadcast_header =  (
    #Request -
        #Block - bacnet_virtual_link_control
        b'\x81'  #Byte - type_bvlc
        b'\x0b'  #Byte - function_bvlc
        b'\x00\x18'  #Word - length_bvlc

        #Block - bacnet_npdu
        b'\x01'  #Byte - version_bacnet
        b'\x20'  #Byte - control_bacnet
        b'\xff\xff' # Long -Dest Network (broadcast)
        b'\x00' # Byte - Dest MAC
        b'\xff' # Hop count
)

sc_broadcast_header  = (
    b'\x01'  # Byte - function bvlc Encapsulated-NPDU
    b'\x04'  # Byte - control flags
    b'\x12\x34'  # 2 Bytes - Message ID
    b'\xFF\xFF\xFF\xFF\xFF\xFF'
    b'\x01'  # Byte - version_bacnet
    b'\x20'  # Byte - control_bacnet
    b'\xFF\xFF'# Dnet
    b'\x00'# Dlen
    b'\xFF'# Hop count
)

class BACnet_Ip(BACnet_Data_Link):
    """Implements BACnet over IP communication using UDP."""
    def __init__(self, ip, port, timeout=2.0):
        """
        Initializes a BACnet over IP object with given IP, port, and timeout.

        :param ip: IP address to send messages to.
        :param port: Port number to send messages to.
        :param timeout: Timeout for waiting on a response (default is 2.0 seconds).
        """
        self.ip = ip
        self.port = port
        self.timeout = timeout

        self.destination =  b''
        self.network_number=1
    
    def current_target_info(self):
        if not self.destination:
            result(f"Direct connection to : {self.ip}:{self.port}\t Network number : {self.network_number}")
        else:
            result(f"Connection over the BBMD  {self.ip}:{self.port} to {self.destination.hex()} ({decode_ip_port(self.destination)}) \t Network number : {self.network_number}")

    


    def get_encapsulated_header(self):
        if self.destination:
            return (
                #Request -
                #Block - bacnet_virtual_link_control
                b'\x81'  #Byte - type_bvlc
                b'\x0a'  #Byte - function_bvlc
                b'\x00\x18'  #Word - length_bvlc

                #Block - bacnet_npdu
                b'\x01'  #Byte - version_bacnet
                b'\x24'  #Byte - control_bacnet
            )+ self.network_number.to_bytes(2,byteorder="big")+ len(self.destination).to_bytes(1,'big') + self.destination + b'\xff'
            

        else:
            return bvlc_header

    def send(self, apdu: BACnetService):
        """Sends a BACnet message over UDP.

        :param apdu: The BACnetService object containing the message to send.
        """
        payload = self.get_encapsulated_header() + apdu.get_bytes()
        if len(payload) > (1 << 16) - 1:
            return
        payload = payload[:2] + len(payload).to_bytes(2, "big") + payload[4:]

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.sendto(payload, (self.ip, self.port))
        except Exception as e:
            fail(f"Error sending UDP packet: {e}")
        finally:
            sock.close()




    def send_and_get(self, apdu : BACnetService):
        """Sends an APDU and waits for a response, handling segmentation.

        :param apdu: The BACnetService object containing the message to send.
        :return: The response from the BACnet service, or None if the request times out.
        """


        if isinstance(apdu, bytes):
            payload = self.get_encapsulated_header() + apdu
        else:
            payload = self.get_encapsulated_header() + apdu.get_bytes()
        
        payload = payload[:2] + len(payload).to_bytes(2, "big") + payload[4:]
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        try:
            sock.sendto(payload, (self.ip, self.port))
            response, addr = sock.recvfrom(2048)  # Buffer size of 2048 bytes
            r=response
            
            # Check for segmentation
            if response[6] & 12 != 12:
                return response
            
            seg=0
            while response[6]&12 == 12:
                ack_payload = self.get_encapsulated_header() + SegAck(seg).get_bytes()
                ack_payload = ack_payload[:2] + len(ack_payload).to_bytes(2, "big") + ack_payload[4:]
                sock.sendto(ack_payload, (self.ip, self.port))
                response, addr = sock.recvfrom(2048)  # Buffer size of 2048 bytes
                r += response[11:]
                seg+=1

            #Send final segment ack
            payload = self.get_encapsulated_header()+SegAck(seg).get_bytes()
            payload = payload[:2] + len(payload).to_bytes(2, "big") + payload[4:]
            sock.sendto(payload, (self.ip, self.port))

            # Remove unnecessary bytes from the response
            r=r[:17]+r[19:]
            return r
            
        except socket.timeout:
            return None
        finally:
            # Close the socket
            sock.close()
    
    def broadcast(self, apdu: BACnetService):
        """Broadcast a BACnet message over UDP.

        :param apdu: The BACnetService object containing the message to send.
        """

        payload = broadcast_header + apdu.get_bytes()
        broadcast_ip =  '.'.join(self.ip.strip().split('.')[:-1] + ['255'])
        print(broadcast_ip)
        if len(payload) > (1 << 16) - 1:
            return
        payload = payload[:2] + len(payload).to_bytes(2, "big") + payload[4:]

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.sendto(payload, (broadcast_ip, self.port))
        except Exception as e:
            print(f"Error sending UDP packet: {e}")
        finally:
            sock.close()
    
    def broadcast_and_get(self, apdu: BACnetService, reception_time = 1.0):
        """Broadcast a BACnet message over UDP.

        :param apdu: The BACnetService object containing the message to send.
        """

        payload = broadcast_header + apdu.get_bytes()
        broadcast_ip =  '.'.join(self.ip.strip().split('.')[:-1] + ['255'])
        if len(payload) > (1 << 16) - 1:
            return
        payload = payload[:2] + len(payload).to_bytes(2, "big") + payload[4:]

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)  # <- Add this line
        sock.settimeout(0.1) 
        sock.bind(("0.0.0.0", 47808))
        responses = []

        try:
            sock.sendto(payload, (broadcast_ip, self.port))
            start_time = time.time()
            while time.time() - start_time < reception_time:
                try:
                    data, addr = sock.recvfrom(4096) 
                    responses.append((data, addr))
                except socket.timeout:
                    continue  # just loop again until reception_time expires

        except Exception as e:
            print(f"Error sending UDP packet: {e}")
        finally:
            sock.close()
        
        return responses




    class bbmd_entry:
        def __init__( self, b : bytes):
            self.ip = b[:4]
            self.port = int.from_bytes(b[4:6],'big')
            self.mask = b[6:]
        
        def __str__(self):
            ip = ".".join(f"{byte}" for byte in self.ip)
            mask = ".".join(f"{byte}" for byte in self.mask)
            return f"{ip}:{self.port}  mask : {mask}"

    def bbmd_distribution_table(self):
        """Get the bbmd distribution table if present"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        payload = b"\x81\x02\x00\x04"
        sock.sendto(payload, (self.ip, self.port))

        response, addr = sock.recvfrom(2048)  # Buffer size of 2048 bytes
        response=response[4:]
        table = []
        if response == b"\x00\x20":
            fail("This device is not a BBMD")
            return None
        for i in range(0, len(response), 10):
            table.append(self.bbmd_entry(response[i:i+10]))

        return table
    
    def bbmd_distribution_table(self):
        """Get the bbmd distribution table if present"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        payload = b"\x81\x02\x00\x04"
        sock.sendto(payload, (self.ip, self.port))

        response, addr = sock.recvfrom(2048)  # Buffer size of 2048 bytes
        response=response[4:]
        table = []
        if response == b"\x00\x20":
            return None
        for i in range(0, len(response), 10):
            table.append(self.bbmd_entry(response[i:i+10]))

        return table

    class fdt_entry:
        def __init__( self, b : bytes):
            self.ip = b[:4]
            self.port = int.from_bytes(b[4:6],'big')
            self.ttl = int.from_bytes(b[6:8],'big')
            self.time_before_purge = int.from_bytes(b[8:10],'big')

        
        def __str__(self):
            ip = ".".join(f"{byte}" for byte in self.ip)
            return f"{ip}:{self.port}  ttl : {self.ttl}  time before purge : {self.time_before_purge}s"
    
    def foreign_device_table(self):
        """Get the bbmd distribution table if present"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        payload = b"\x81\x06\x00\x04"
        sock.sendto(payload, (self.ip, self.port))

        response, addr = sock.recvfrom(2048)  # Buffer size of 2048 bytes
        response=response[4:]
        table = []
        if response == b"\x00\x40":
            return None
        for i in range(0, len(response), 10):
            table.append(self.fdt_entry(response[i:i+10]))

        return table

    def network_info(self):
        """Get and print the bbmd broadcast distribution table if present"""

        entries = self.bbmd_distribution_table()
        if entries is None:
            result("\t-This device is not a BBMD")
        else :
            result("\tBBMD - Broadcast distribution table:")
            for e in entries:
                result(f"\t\t{e}")
            if not entries: result(f"\t\tEmpty")

        entries = self.foreign_device_table()
        if entries is None:
            result("\n\t-This device has no FDT")
        else :
            result("\n\tForeign Device Table:")
            for e in entries:
                result(f"\tt{e}")
            if not entries: result(f"\t\tEmpty")


class BACnet_SC(BACnet_Data_Link):
    """Implements BACnet Secure Connect (BACnet/SC) communication over WebSockets."""
    
    def __init__(self, ip: str, port: int, client_key: str, client_cert: str):
        """Initializes BACnet Secure Connect with IP, port, and client credentials."""
        self.ip = ip
        self.port = port
        self.client_key = client_key
        self.client_cert = client_cert
        self.destination= b''
    
    def current_target_info(self):
        if self.destination:
            result(f"Direct connection to : {self.ip}:{self.port}")
        else:
            result(f"Connection over the Hub  {self.ip}:{self.port} to {self.destination.hex()} ({decode_ip_port(self.destination)}) \t Network number : {self.network_number}")


    def get_encapsulated_NPDU_header():
        if self.destination:
            return (
                b'\x01'  # Byte - function bvlc
                b'\x04'  # Byte - control flags
                b'\x12\x34'  # 2 Bytes - Message ID
                )+ self.destination + (
                b'\x01'  # Byte - version_bacnet
                b'\x04'  # Byte - control_bacnet
            ) 
        else:
            return encapsulated_NPDU_header


    def bruteforce(self, pwd_list_file: str, start_index=0):
        """Optimisazion for bruteforce for ws"""
        return asyncio.run(self._bruteforce(pwd_list_file, start_index))
    
    def send(self, apdu: BACnetService):
        """Sends an APDU over WebSockets."""
        encapsulated_NPDU = self.get_encapsulated_NPDU_header() + apdu.get_bytes()

        return asyncio.run(self._send_async(encapsulated_NPDU))
    
    def send_and_get(self, apdu: BACnetService):
        """Sends an APDU and waits for a response over WebSockets."""
        encapsulated_NPDU = self.get_encapsulated_NPDU_header() + apdu.get_bytes()
                
        return b'\x81\x0a\x00\x00' + asyncio.run(self._send_and_get_async(encapsulated_NPDU))["payload"]
    
    def connect_ws(self):
        """Establishes a WebSocket connection."""
        return asyncio.run(self._connect_ws())

    def _create_ssl_context(self):
        """Creates an SSL context for WebSocket connections."""
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        ssl_context.load_cert_chain(certfile=self.client_cert, keyfile=self.client_key)
        return ssl_context


    async def _send_async(self, payload: bytes):
        """Sends an APDU asynchronously over WebSockets."""
        url = f"wss://{self.ip}:{self.port}"

        ssl_context = self._create_ssl_context()

        try:
            async with websockets.connect(url, ssl=ssl_context) as ws:
                await ws.send(connect_request)
                message = await ws.recv()
                if message[0] != 7:
                    fail(f"\tConnection was not Accepted")
                await ws.send(payload)
        except websockets.exceptions.ConnectionClosedOK:
            info("Connection closed normally by server.")
        return None

    async def _send_and_get_async(self, payload: bytes, a=False):
        """Sends an APDU and waits for a response asynchronously over WebSockets."""
        url = f"wss://{self.ip}:{self.port}"

        ssl_context = self._create_ssl_context()

        try:
            async with websockets.connect(url, ssl=ssl_context) as ws:
                # Connect
                await ws.send(connect_request)
                message = await ws.recv()

                if message[0] != 7:
                    fail(f"\tConnection was not Accepted")

                await ws.send(payload)
                message = await ws.recv()

                return decode_received_message(message)
        except websockets.exceptions.ConnectionClosedOK:
            info("Connection closed normally by server.")
        return None

    async def _send_and_collect_async(self, payload: bytes, duration: float, a=False):
        url = f"wss://{self.ip}:{self.port}"
        ssl_context = self._create_ssl_context()
        responses = []

        try:
            async with websockets.connect(url, ssl=ssl_context) as ws:
                # Initial handshake
                await ws.send(connect_request)
                message = await ws.recv()
                if message[0] != 7:
                    fail("\tConnection was not Accepted")

                # Send payload
                await ws.send(payload)

                # Collect responses for the given duration
                end_time = datetime.utcnow() + timedelta(milliseconds=duration)
                while datetime.utcnow() < end_time:
                    try:
                        # Timeout ensures we don't block forever if no message comes
                        message = await asyncio.wait_for(ws.recv(), timeout=1)
                        decoded = decode_received_message(message)
                        responses.append(decoded)
                    except asyncio.TimeoutError:
                        # No message in 1 second, continue waiting
                        continue

            return responses

        except websockets.exceptions.ConnectionClosedOK:
          info("Connection closed normally by server.")

        return responses

    def address_resolution(self):
        """Get the list of all WebSocket URIs at which the device node accept connections"""
        return (asyncio.run(self._send_and_get_async(b"\x02\x00\x12\34"))["payload"]).split()

    def advertisement(self):
        """Send an advertisement solicitation and get the response"""
        return asyncio.run(self._send_and_get_async(b"\x05\x00\x12\34"))["payload"]


    def network_info(self):

        adv = self.advertisement()
        for k, v in adv.items():
            result(f"\t{k:<30}: {v}")


        uris = self.address_resolution()
    
        result("\tWebSockets URIs:")
        for u in uris:
            result(f"\t\t-{u}")
        if not uris: result(f"\t\tNone")
        

    def broadcast(self,service):
        payload =sc_broadcast_header + service.get_bytes()
        resp = asyncio.run(self._send_and_collect_async(payload, 1000))
        return resp
        
    def broadcast_and_get(self,service):
        payload =sc_broadcast_header + service.get_bytes()
        resp = asyncio.run(self._send_and_collect_async(payload, 1000))
        return resp



    async def _bruteforce(self, pwd_list_file : str, start_index = 0):
        """Performs a brute-force attack using a password list file."""
        url = f"wss://{self.ip}:{self.port}"
        ssl_context = self._create_ssl_context()

        async with websockets.connect(url, ssl=ssl_context) as ws:
            await ws.send(connect_request)
            message = await ws.recv()
            if message[0] != 7:
                fail(f"\tConnection was not Accepted")
            
            i=-1
            try :
                async with aiofiles.open(pwd_list_file, "r") as pwd_list:
                    async for pwd in pwd_list:
                        i+=1

                        if i<start_index:
                            continue                 
                        
                        pwd=pwd.strip()
                        if(len(pwd)<4):
                            continue

                        sys.stdout.write(" " * 50)
                        sys.stdout.write("\r")
                        sys.stdout.write(f"\t{Fore.CYAN}Testing: {pwd.strip()}\r{Style.RESET_ALL}")  # Write to stdout, overwrite previous line
                        sys.stdout.flush()

                        password_char = (len(pwd) + 1).to_bytes(1,'little') + b'\x00' + pwd.encode()
                        encapsulated_NPDU = self.get_encapsulated_NPDU_header() +BACnetService(0,20, [
                            BACnetObject(0,1,1, b'\x00'),
                            BACnetObject(1,1,5, password_char)
                        ]).get_bytes()
                        
                        await ws.send(encapsulated_NPDU)
                        message = await ws.recv()

                        if message is None:
                            fail(f"\n\tConnection Failed for password : {pwd} index : {i} ")
                            continue
                        
                        resp =  b'\x00\x00\x00\x00' + decode_received_message(message)["payload"]

                        if resp[6] == 0x60:
                            fail(f"Non security Error [{reject_reason[resp[8]]}] received for password : {pwd} index : {i}")
                            continue
                        if resp[6] ==0x50:
                            if resp[10] == 0x04: 
                                continue
                            fail(f"\n\tNon security Error received for password : {pwd} index : {i}")
                            continue
                        success(f"\n\tPassword found : {pwd} index : {i}")
                        return
            except FileNotFoundError:
                fail(f"Error: The file '{pwd_list_file}' was not found.")
            except PermissionError:
                success(f"Error: Permission denied while trying to open '{pwd_list_file}'.")

        return None

    async def _connect_ws(self):
        """Attempts to establish a WebSocket connection."""
        url = f"wss://{self.ip}:{self.port}"
        ssl_context = self._create_ssl_context()

        try:
            async with websockets.connect(url, ssl=ssl_context) as ws:
                # Connect
                await ws.send(connect_request)
                message = await ws.recv()
                if message[0] != 7:
                    return "Connection_Refused"
                return "OK"
        except websockets.exceptions.WebSocketException:
            return "Bad_certificate"
        except ConnectionRefusedError as e:
            return "No_WS"
        except Exception as e:
            return "No_WS"



