import shlex
import os
import readline
import argparse
from colorama import Fore, Style

from utils import *
from bacnet.service import all_service
from bacnet.datalink import *

import modules.actions as actions
import modules.recon as recon
import modules.attacks  as attacks
import modules.fuzzer as fuzzer
import modules.scan as scan


logo = '''                         0100001001                         
                   0000010100001101110100                   
            011001010111001       001101001011000           
        0101000010010     __--^--__    0000101000011        
        0111010       __--         --__       0011001       
        0101      __--                 --__      1100       
        1001     -__                     __-     1010       
        0101     |  --__             __--  |     1000       
        0101     ||-_   --__     __--   _-||     0000       
        1001     | -_||-_   --_--   _-||_- |     0000       
        0101     |     -_||-_ | _-||_-     |     0000       
        1101     ||-_      -_|||_-      _-||     1101       
        0001     | -_||-_     |     _-||_- |     1001       
        0101     |     -_||-_ | _-||_-     |     1100       
        1001     ||-_      -_|||_-      _-||     1010       
        01011    | -_||-_     |     _-||_- |    00001       
         01000   |     -_||-_ | _-||_-     |   01001        
          000001 ||-_      -_|||_-      _-|| 010000         
            11011||-_||-_     |     _-||_- |10100           
             0110010   -_||-_ | _-||_-   101110             
               0100110     -_|||_-     1001011              
                  0000101     |     0000100                 
                    100000101 | 0000110                     
                       11101000110010                       
                          10111001                          '''


title = r'''     ____    ____     _____    __                  _        
    / __ )  /   |   /´____/ __/ /_   __    _ ___  (_)  ___ _
   / __  | / /| |  / /     /_  __/ /´_ \  / ´__/ / / /´__ `/
  / /_/ / / ___ | / /___    / /_  /  __/ / /´   / / / /_/ / 
 /_____/ /_/  |_| \____/    \__/  \___/ /_/    /_/  \__,_/  
BACnet Testing, Enumeration, Recon, Injection And fuzzing   
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++   
'''
        
class FuzzingCLI:

    cli_command= ["info", "alarm_summary", "find_devices","target", "connect","set_network_number", "event_info","network_info","device_properties","services_supported","create","delete","reinitialize","objects_supported","list_objects","properties","dump", "set_property", "set_property_at_index","bruteforce", "clear", "new_fuzzing","resume_fuzzing","load_fuzzing","fuzzing_sessions","change_time","time_wraparound","enable","disable","exit"]

    fuzzing_command = ["show","fuzz", "run",  "goto", "clear", "exit", "raw"]


    def __init__(self,dl : BACnet_Data_Link):
        self.commands = self.cli_command
        self.setup_autocomplete()
        self.is_fuzzing = False
        self.fuzzing_session = None
        self.fuzzing_session_list = []
        self.dl = dl


    ##### FUZZING FUNCTIONALITY #####
    def show(self):
        """Print the current fuzzing case."""
        self.fuzzing_session.show()    
    def raw(self):
        """Print the raw packet content current fuzzing case."""
        self.fuzzing_session.raw()    
    def fuzz_current(self):
        """Run the current fuzzing case and stop."""
        self.fuzzing_session.fuzz_current()
    def run_all(self):
        """Run all fuzzing case until a crash is detected."""
        self.fuzzing_session.run_all()
    def goto(self, index):
        """Go to a given fuzzing case"""
        self.fuzzing_session.goto(index)
    def create_fuzzing(self, service):
        """Create a fuzzing session"""
        serv = all_service.get(service, None)
        if serv == None:
            fail(f"Unhandled Service. Must be in {list(all_service.keys())}")
            return 
        self.fuzzing_session = fuzzer.FuzzingSession(self.dl, len(self.fuzzing_session_list),serv,service,100)
        self.fuzzing_session_list.append(self.fuzzing_session)
        self.is_fuzzing = True
        self.commands = self.fuzzing_command
    def load_fuzzing(self, id):
        """load a fuzzing session"""
        if id >= len(self.fuzzing_session_list):
            fail(f"Unvalid session id ")
            return
        self.fuzzing_session = self.fuzzing_session_list[id]
        self.is_fuzzing=True
    def resume_fuzzing(self):
        """Resume the last fuzzing session"""
        self.is_fuzzing=True
    def fuzzing_sessions(self):
        """list the active fuzzing session"""
        for i,s in enumerate(self.fuzzing_session_list):
            result(f"{i:<5}: {s.service}") 

    ##### RECON FUNCTIONALITY #####
    def  info(self):
        """List device info"""
        recon.infos(self.dl)
    def device_properties(self):
        """List all device properties"""
        recon.device_properties(self.dl)
    def alarm_summary(self):
        """List the alarm summary of the device"""
        recon.alarm_summary(self.dl)
    def event_info(self):
        """List the event info of the device"""
        recon.event_info(self.dl)
    def  services(self):
        """List all supported service"""
        recon.service_supported(self.dl)
    def  objects(self):
        """List all supported object type"""
        recon.object_types_supported(self.dl)
    def list_objects(self):
        """List all objects on th device"""
        recon.list_objects_info(self.dl)
    def properties(self, obj_type, instance):
        """List all properties of an object"""
        recon.object_properties(self.dl, obj_type, instance )
    def network_info(self):
        """Show different info on the nerwork link"""
        self.dl.network_info()
    def find_devices(self):
        """Send whois message to enumerate device"""
        recon.find_devices(self.dl)

    ##### ACTION FUNCTIONALITY ##### 
    def create(self,obj_type, instance):
        """Create a new object"""
        actions.create(self.dl, obj_type, instance)
    def delete(self,obj_type, instance):
        """Delete an object"""
        actions.delete(self.dl, obj_type, instance)
    def reinit(self,state, pwd):
        """ Reinitialize a device to a given state"""
        actions.reinit(self.dl, state, pwd)
    def enable(self, pwd):
        """Enable a disabled device"""
        actions.device_communication(self.dl, True, pwd)
    def disable(self, pwd):
        """Disable a device"""
        actions.device_communication(self.dl, False, pwd)
    def dump(self, instance, file_name=""):
        """Dump a file to /dump"""
        actions.read_atomic(self.dl, instance, file_name)
    def set_property(self,obj_type : str, instance : int, properti: str, val_type : str, value : str, priority :int):
        """Set the property value of an object"""
        actions.write_property_object_value(self.dl, obj_type, instance, properti, val_type, value, priority)
    def set_property_at_index(self,obj_type : str, instance : int, properti: str, val_type : str, value : str, priority :int,index=int):
        """Set the property value of an object at a given index"""
        actions.write_property_object_value_index(self.dl, obj_type, instance, properti, val_type, value, priority, index)
    def change_time(self, date:str,time:str):
        """Change time on the device"""
        actions.set_time(self.dl, date,time)
    def connect(self, vmac):
        """connect to another device via the current one"""
        actions.connect(self.dl, vmac)
    def set_network_number(self,n):
        """change the network number"""
        actions.set_network_number(self.dl,n)

    ##### ATTACK FUNCTIONALITY #####
    def bruteforce(self, list : str, index : int=0):
        """Bruteforce BACnet password"""
        attacks.bruteforce(self.dl, list, index)
    def time_wraparound(self):
        """Run time wraparound attacks """
        attacks.time_wraparound(self.dl)

    ##### UTILS FUNCTIONALITY #####
    def clear(self):
        """Clear the terminal screen."""
        os.system('cls' if os.name == 'nt' else 'clear')
    def help(self):
        """Display available commands."""
        success(f"Available commands:")
        info(f"===Recon===")        
        info(f"\tinfo - Show basic information on the target device (Based on https://svn.nmap.org/nmap/scripts/bacnet-info.nse)")        
        info(f"\tdevice_properties - Enumerate all property on the machine")        
        info(f"\tservices_supported - Enumerate all service the device support")        
        info(f"\tobjects_supported - Enumerate all object types the device support")        
        info(f"\tlist_objects - Enumerate all objects on the device")
        info(f"\tproperties <type>:<instance> - Enumerate all property of an object")
        info(f"\tevent_info - List all active events state")
        info(f"\tnetwork_info - Show all info about the network link ")
        info(f"\tfind_devices - Enumerate devices reachable from the current device")

        info(f"===Fuzzing===")        
        info(f"\tnew_fuzzing <service> - Create a new fuzzing session for the given service.")
        info(f"\tresume_fuzzing  - Resume the last fuzzing session.")
        info(f"\tload_fuzzing <id> - Load a given fuzzing session.")
        info(f"\tfuzzing_sessions  - List all active fuzzing session.")

        info(f"===Action===")
        info(f"\tdump <instance> <?filename> - Dump a file from the device")
        info(f"\tset_property <obj_type> <obj_instance> <property> <value_type> <value> <priority>- Set a property of an object to a given value")
        info(f"\tset_property_at_index <obj_type> <obj_instance> <property> <value_type> <value> <priority> <index>- Set a field of property of an object at the given index to a given value")
        info(f"\tcreate <obj_type> <obj_instance> - Create an object of the given type and instance")
        info(f"\tdelete <obj_type> <obj_instance> - Delete an object of the given type and instance")
        info(f"\treinitialize <state> <password> - Renitialize the device in a given state")
        info(f"\tenable <password> - Enable the device")
        info(f"\tdisable <password> - Disable the device until next enable or reinit")
        info(f"\tchange_time <date> <time>  - Set device clock to the given value")


        info(f"===Attacks===")
        info(f"\tbruteforce <wordlist> <?index> - Bruteforce BACnet credentials (need reinitializeDevice supported by the device).")
        info(f"\ttime_wraparound  - Change time after 19.01.2038 making service using 32bit timestamp crash.")

        info(f"===Utils===")
        info(f"\ttarget - print information on the current target connection")
        info(f"\tconnect <?vmac> - connect to another device in network via the current one (use find_devices for possible devices)")
        info(f"\tset_network_number <n> - change the network number of the communication")      
        info(f"\tclear - Clear the terminal screen.")
        info(f"\thelp - Show this help message.")
        info(f"\texit - Exit the CLI.")
    
    def help_fuzz(self):
        """Display available commands."""
        success(f"Available commands:")
        info(f"===Fuzzing===")        
        info(f"\tshow - Display the current fuzzing case.")
        info(f"\traw - Display the current fuzzing case in raw bytes.")
        info(f"\tfuzz - Run the current fuzzing case and stop.")
        info(f"\trun - Run all fuzzing cases from the current position until a crash occurs.")
        info(f"\tgoto <n> - Move to the nth fuzzing case.")
        
        info(f"===Utils===")        
        info(f"\tclear - Clear the terminal screen.")
        info(f"\thelp - Show this help message.")
        info(f"\texit - Exit the CLI.")

    def setup_autocomplete(self):
        """Setup command-line autocompletion."""
        def completer(text, state):
            options = [cmd for cmd in self.commands if cmd.startswith(text)]
            return options[state] if state < len(options) else None

        readline.parse_and_bind("tab: complete")
        readline.set_completer(completer)

    def start(self):
        """Start the CLI loop."""
        #success(f"                          ⣀⣀⣤⡶⣾⢿⡷                 \n\t                    ⢀⣰⡶⣶⣞⣿⡽⣯⣷⠿⠟⢯⣿⣥⢰⡂⡀             \n\t               ⣀⣀⣤⡶⣾⣻⣿⣻⠳⢛⣺⣭⣵⡶⣾⣖⡄⠙⢶⣭⣿⣶⣂⡀           \n\t        ⢀⣤⣴⣲⢶⣞⡿⣯⣟⡷⠻⢻⢻⠓⢁⣴⣿⣻⢽⣷⢿⡷⣯⠟⠖⠄⠑⠛⢾⣟⣾⢦⡀         \n\t       ⢠⣾⡻⡞⠯⠛⠚⠉⠁⠁  ⠈⠁⠐⠿⣳⣯⣟⣿⣻⢯⡿⠋     ⠈⠸⢯⣿⡽⣦⢄       \n\t      ⣰⡿⣏⠏⣴⣖⣤          ⠘⢷⣷⣝⣅⠉          ⢹⡿⣽⡟       \n\t     ⣰⡿⣽⠇⣘⠓⠉⠁    ⢀⣀⣀⣤⣔⣲⣂⣤⣄⣀⢉⢀⣀⡀⣀⣀⣤⣤⠄  ⢀⣿⣟⣷⠁       \n\t     ⠿⠿⢻⣿⣳⢿⣔⣤⣔⣶⢶⡿⣷⣻⣽⣾⣻⣽⣻⠽⠯⣟⣯⡿⣞⡿⠽⠋⠈    ⣠⣝⣫⡅⡀       \n\t       ⢲⣠⢉⠛⢯⡿⣽⣾⣿⣽⣻⣻⣷⢟⣝⡫⠟⠁   ⠈⠁   ⣠⡄  ⣼⢿⡽⣯⢿⢶⣄      \n\t        ⠙⣷⣧⣆⣝⢿⣻⡾⣽⣻⣷⣽⡾⣟⣾⣢⣄⢀⡀   ⣀⣴⣾⢷⣷⢶⣦⣟⣭⡷⡟⣿⣿⡵⣆     \n\t         ⠈⠳⢻⣯⣿⣯⣟⡿⣳⠟⠾⢽⣟⡷⣿⣽⣻⢾⣷⡴⣾⣻⡽⠂⢸⣿⣻⢾⣽⢯⣿⣯ ⠙⢽⣟     \n\t          ⣠⣶⢮⣴⡀    ⢀⣼⢯⡿⠃⠁⠉⠙⠚⠿⠗⠉  ⣴⢿⣯⣟⣯⣿⣻⢷⣗⡄⠘⣯     \n\t         ⡼⣿⢾⣻⣯⣟⣤⣤⡤⣀⡾⡭⠋          ⢸⣟⡿⣞⣿⠟⠾⢿⢯⣟⡿⣄⠁     \n\t        ⢰⣷⣟⠿⣿⡿⣯⣟⣾⣽⡟⠂           ⣠⠹⣯⣟⣿⢿⣥⠄⡀⠈⠙⠻⡿⣅     \n\t        ⢸⣟⠂⣠⣿⡻⣷⣻⣽⣾⣗⡄ ⡀       ⣠⣾⢿⣴⠌⠒⠛⠯⠻⠟⠛⠃  ⠈⠙⠂    \n\t         ⠻⢰⡿⣹⢿⡝⢿⣿⣟⣾⣻⢸⣶⣂⡀   ⣠⣾⣟⡾⡯⠊                 \n\t         ⢠⣿⠻⠝⢁⣠⣼⠾⣺⣷⠛⠸⣽⣻⣶⣂⣠⣾⣻⢷⡫⠊                   \n\t         ⠸⠅⠁ ⠈⠁⠋⠉⠁   ⠈⠳⣯⣿⣻⢾⠽⠊                     \n\t                       ⠈⢺⡏⠃ ")
        success(f"{logo}\n{Fore.YELLOW}{title}")
       # success(f"________________________                     _____              \n___  __ )__    |_  ____/__________  ___________  /______________\n__  __  |_  /| |  /    __  ___/  / / /__  __ \  __/  __ \_  ___/\n_  /_/ /_  ___ / /___  _  /   / /_/ /__  /_/ / /_ / /_/ /  /    \n/_____/ /_/  |_\____/  /_/    \__,_/ _  .___/\__/ \____//_/     \n                                     /_/       ")
        success(f"BACteria CLI started. Type 'help' for available commands.")
        
        if self.dl.port is None:
            ports = scan.scan_port(self.dl.ip)
            self.dl = scan.choose_port(self.dl.ip, ports)
            if self.dl is None:
                fail(f"No running BACnet instance found : Exiting")
                return
       
        while True:
            if self.is_fuzzing:
                prompt = f"{Fore.YELLOW}[{self.fuzzing_session.current_case + 1} over {len(self.fuzzing_session.fuzzing_cases)} cases] fuzz-cli> "
                command = input(prompt).strip()                
                if not command:
                    continue
                args = shlex.split(command)
                cmd = args[0].lower()
                if cmd == "show":
                    self.show()
                elif cmd == "raw":
                    self.raw()
                elif cmd == "fuzz":
                    self.fuzz_current()
                elif cmd == "run":
                    self.run_all()
                elif cmd == "goto":
                    if len(args) > 1 and args[1].isdigit():
                        self.goto(int(args[1]))
                    else:
                        fail(f"Usage: goto <case_number>")
                elif cmd == "clear":
                    self.clear()
                elif cmd == "help":
                    self.help_fuzz()
                elif cmd == "exit":
                    fail(f"Exiting Fuzzing Session")
                    self.is_fuzzing = False
                    self.commands = self.cli_command
                else:
                    fail(f"Unknown command. ")

            else : 
                prompt = f"{Fore.YELLOW}[BACteria]> "
                command = input(prompt).strip()
                try:                
                    if not command:
                        continue
                    args = shlex.split(command)
                    cmd = args[0].lower()
                    if cmd == "device_properties":
                        self.  device_properties()
                    elif cmd == "info":
                        self.info()
                    elif cmd == "services_supported":
                        self.services()
                    elif cmd == "objects_supported":
                        self.objects()
                    elif cmd == "network_info":
                        self.network_info()
                    elif cmd == "list_objects":
                        self.list_objects()
                    elif cmd == "alarm_summary":
                        self.alarm_summary()
                    elif cmd == "event_info":
                        self.event_info()
                    elif cmd == "find_devices":
                        self.find_devices()
                    elif cmd == "connect":
                        if len(args) > 1 and args[1].isascii():
                            self.connect(str(args[1]))
                        else:
                            self.connect("")
                    elif cmd == "set_network_number":
                        if len(args) > 1 and args[1].isdigit():
                            self.set_network_number(int(args[1]))
                        else:
                            fail(f"Usage: set_network_number <n>")
                    elif cmd == "target":
                        self.dl.current_target_info()
                    elif cmd == "dump":
                        if len(args) > 2 and args[1].isdigit() and args[2].isascii():
                            self.dump(int(args[1]),str(args[2]))
                        if len(args) > 1 and args[1].isdigit():
                            self.dump(int(args[1]))
                        else:
                            fail(f"Usage: dump <instance> <?filename>")
                    elif cmd == "set_property":
                        if len(args) > 5 and args[1].isascii() and args[2].isascii() and args[3].isascii() and args[4].isascii() and args[5].isdigit():
                            t,i = parse_object_identifier(args[1])
                            if not i or not t : continue
                            self.set_property(t,i,args[2], args[3], args[4], int(args[5]))
                        else:
                            fail(f"Usage: set_property <obj_type>:<obj_instance> <propeerty> <value_type> <value> <priority>")
                    elif cmd == "set_property_at_index":
                        if len(args) > 6 and args[1].isascii() and args[2].isascii() and args[3].isascii() and args[4].isascii() and args[6].isdigit() and args[6].isdigit():
                            t,i = parse_object_identifier(args[1])
                            if not i or not t : continue
                            self.set_property_at_index(t,i,args[2], args[3], args[4], int(args[5]), int(args[6]))
                        else:
                            fail(f"Usage: set_property_at_index <obj_type>:<obj_instance> <propeerty> <value_type> <value> <priority>")
                    
                    elif cmd == "create":
                        if len(args) > 2 and args[1].isascii() and args[2].isdigit():
                            self.create(args[1],int(args[2]))
                        else:
                            fail(f"Usage: create <obj_type> <obj_instance>")
                    elif cmd == "delete":
                        if len(args) > 2 and args[1].isascii() and args[2].isdigit():
                            self.delete(args[1],int(args[2]))
                        else:
                            fail(f"Usage: delete <obj_type> <obj_instance>")
                    elif cmd == "reinitialize":
                        if len(args)==2  and args[1].isascii():
                            self.reinit(str(args[1]),None)
                        elif len(args) > 2 and args[1].isascii() and args[2].isascii():
                            self.reinit(str(args[1]),str(args[2]))
                        else:
                            fail(f"Usage: reinitialze <state> <password>")
                    elif cmd == "enable":
                        if len(args)==1:
                            self.enable(None)
                        elif len(args) > 1 and args[1].isascii():
                            self.enable(str(args[1]))
                        else:
                            fail(f"Usage: enable <password>")
                    elif cmd == "disable":
                        if len(args)==1:
                            self.disable(None)
                        elif len(args) > 1 and args[1].isascii():
                            self.disable(str(args[1]))
                        else:
                            fail(f"Usage: disable <password>")
                    elif cmd == "properties":
                        if len(args) > 1 and args[1].isascii():
                            t,i = parse_object_identifier(args[1])
                            if not i or not t : continue
                            self.properties(t,i)
                        else:
                            fail(f"Usage: properties <type>:<instance>")
                    elif cmd == "new_fuzzing":
                        if len(args) > 1 and args[1].isascii():
                            self.create_fuzzing(str(args[1]))
                        else:
                            fail(f"Usage: new_fuzzing <service>")
                    elif cmd == "load_fuzzing":
                        if len(args) > 1 and args[1].isdigit():
                            self.load_fuzzing(int(args[1]))
                        else:
                            fail(f"Usage: load_fuzzing <id>")
                    elif cmd == "resume_fuzzing":
                        self.resume_fuzzing()
                    elif cmd == "fuzzing_sessions":
                        self.fuzzing_sessions()
                    elif cmd == "clear":
                        self.clear()
                    elif cmd == "help":
                        self.help()
                    elif cmd == "time_wraparound":
                        self.time_wraparound()
                    elif cmd == "exit":
                        fail(f"Exiting...")
                        break
                    elif cmd == "bruteforce":
                        if len(args) > 2 and args[2].isdigit() and args[1].isascii():
                            self.bruteforce(str(args[1]),int(args[2]))
                        elif len(args) > 1 and args[1].isascii():
                            self.bruteforce(str(args[1]))
                        else:
                            fail(f"Usage: bruteforce <wordlist> <index>")
                    elif cmd == "change_time":
                        if len(args) > 2 and args[2].isascii() and args[1].isascii():
                            self.change_time(str(args[1]),str(args[2]))
                        else:
                            fail(f"Usage: change_time <date> <time>")
                    else:
                        fail(f"Unknown command. Do help for list of command")
                except KeyboardInterrupt:
                    fail(f"Action stopped by Keyboard Interrupt")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fuzzing CLI Argument Parser")
    parser.add_argument("target_ip", type=str, help="Target IP address")
    parser.add_argument("target_port", type=int, nargs="?", help="Target Port number (optional)")
    
    parser.add_argument("-sc", action="store_true", help="Connect as BACnet(SC) (optional)")

    # Add 'client-cert' and 'client-key' as optional arguments that only appear if '-sc' is used
    parser.add_argument("client_key", type=str, nargs="?", help="Path to the client key (optional)", default="cert/self-signed-key.pem")
    parser.add_argument("client_cert", type=str, nargs="?", help="Path to the client certificate (optional)", default="cert/self-signed-cert.pem")

    args = parser.parse_args()
    dl=None
    if args.sc :
        dl = BACnet_SC(args.target_ip,args.target_port,args.client_key,args.client_cert)
    else:
        dl =BACnet_Ip(args.target_ip,args.target_port)

    cli = FuzzingCLI(dl)
    try:
        cli.start()
    except KeyboardInterrupt:
                    fail(f"Exiting...")