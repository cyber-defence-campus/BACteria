import socket
import time
from utils import *

from bacnet.service import BACnetService, all_service
from bacnet.object import get_random_app_object_valid_struct as generate_random_object
from bacnet.object import get_random_app_object_valid_size as generate_random_valid_object
from bacnet.object import get_random_app_object_incoherent_length as generate_random_incoherent_object
from bacnet.object import BACnetObject, BACnetObjectList

import random
from bacnet.datalink import bvlc_header, BACnet_Data_Link

class FuzzingCase():
    """ A fuzzing case"""
    def __init__(self,service : BACnetService, desc : str):
        """inititate a Fuzzing case.

        :param service: The fuzzing data to send
        :param desc : a description of the case
        """
        self.service=service
        self.desc = desc
    
    def __str__(self):
        return f"{self.desc}\n{self.service}"

def flaten_object_list(object_list):
    """ Take an object list and flatten the inner listto only one continus list

    param object_list: the list to flatten
    :return a flatten list
    """
    new_list=[]
    for o in object_list:
        if type(o) is BACnetObject:
            new_list.append(o)
        elif type(o) is BACnetObjectList:
            new_list.append(BACnetObject(o.opening_tag,1,6))
            new_list.extend(flaten_object_list(o.objects))
            new_list.append(BACnetObject(o.opening_tag,1,7))
    return new_list


class FuzzingSession():
    '''A fuzzing session '''
    def generate_Fuzzing_case(self, service : BACnetService, nb_case : int ):

        service.objects=flaten_object_list(service.objects)
        fuzzing_cases = [FuzzingCase(service.copy(), "Basic Case")]

        ##### 1. change object value #######
        
        #1.1 one by one
        for i,obj in enumerate(service.objects) :
            
            new_case = service.copy()
            new_case.objects[i].value = b"\x00"* len(obj.value)
            fuzzing_cases.append(FuzzingCase(new_case,f"Min value of object {i}" ))

            new_case = service.copy()
            new_case.objects[i].value = b"\xFF"* len(obj.value)
            fuzzing_cases.append(FuzzingCase(new_case,f"Max value of object {i}" ))

            for _ in range(nb_case):
                new_case = service.copy()
                new_case.objects[i].value = bytes(random.choices(range(256),k=len(obj.value)))
                fuzzing_cases.append(FuzzingCase(new_case,f"Random value of object {i}" ))
        
        #1.2 all together
        for _ in range(nb_case):
            new_case = service.copy()
            for i,obj in enumerate(service.objects) :                
                if obj.length in [6,7]:continue
                new_case.objects[i].value = bytes(random.choices(range(256),k=len(obj.value)))
            fuzzing_cases.append(FuzzingCase(new_case,f"Random value on all objects" ))
    
        #1.3 change object value & length
        for i,obj in enumerate(service.objects) :
            
            if obj.length in [6,7]:continue
            for _ in range(nb_case):
                new_case = service.copy()
                new_case.objects[i] = generate_random_object(obj.obj_type)
                fuzzing_cases.append(FuzzingCase(new_case,f"Random value on object {i} (different length)" ))

        ##### 2. change object type #######

        #2.1 one by one
        for i,obj in enumerate(service.objects) :
            

            #2.1 change only object tag
            for _ in range(nb_case):
                new_case = service.copy()
                new_case.objects[i].obj_type = random.randint(0,12)
                fuzzing_cases.append(FuzzingCase(new_case,f"Random tag type on  object {i}" ))
            
            #2.1 change the whole object
            for _ in range(nb_case):
                new_case = service.copy()
                new_case.objects[i] = generate_random_valid_object()
                fuzzing_cases.append(FuzzingCase(new_case,f"Random object on  object {i}" ))
        
        #2.3 All together
        for _ in range(nb_case*10):
            new_case = service.copy()
                    
            for i,obj in enumerate(service.objects) :
                

                if obj.length in [6,7]:continue
                new_case.objects[i] = generate_random_valid_object()
            
            fuzzing_cases.append(FuzzingCase(new_case,f"Random object on  all object" ))

        # 2.5 Service confusion
        for k,v in all_service.items():
            new_case =service.copy()
            new_case.objects = v.objects
            fuzzing_cases.append(FuzzingCase(new_case,f"Other service object suit ({k})" ))

        ######## 3 Uncoherent length ########
        
        #3.1 modify object such that tag:lenth and effective length are not similar
        for i,obj in enumerate(service.objects) :
        
            #2.1 change only length tag
            for _ in range(nb_case):
                new_case = service.copy()
                new_case.objects[i].length = random.randint(0,5)
                fuzzing_cases.append(FuzzingCase(new_case,f"Random tag length on object {i}" ))
            
            #2.1 change the whole object
            for _ in range(nb_case):
                new_case = service.copy()
                new_case.objects[i] = generate_random_incoherent_object()
                fuzzing_cases.append(FuzzingCase(new_case,f"Random object with uncoherent length on object {i}" ))

        #2.3 All together
        for _ in range(nb_case*10):
            new_case = service.copy()
                    
            for i,obj in enumerate(service.objects) :
                
                if obj.length in [6,7]:continue
                new_case.objects[i] = generate_random_incoherent_object()
            
            fuzzing_cases.append(FuzzingCase(new_case,f"Random object with uncoherent length on all objects" ))

        return fuzzing_cases

    def __init__(self,dl : BACnet_Data_Link, session_id : int, service : BACnetService,service_name : str, nb_case : int):
        """inititate a Fuzzing session.

        :param dl: The BACnet data link object used for communication.
        :param session_id: The id of the session
        :param service: The Bacnet service to fuzz.
        :param ervice_name: The naem of the service to fuzz
        :param nb_case: The number of fuzzing case for each fuzzing category
        """
        self.dl = dl
        self.service=service_name
        info(f"\tGenerating Fuzzing cases...")
        self.fuzzing_cases = self.generate_Fuzzing_case(service, nb_case)
        info(f"\t{len(self.fuzzing_cases)} fuzzing cases were generated.")
        self.current_case = 0
    
    def show(self):
        """Print the current fuzzing case."""
        result(f"Current Case [{self.current_case + 1}]: {self.fuzzing_cases[self.current_case]}")

    def raw(self):
        """Print the raw packet content current fuzzing case."""
        result(f"Current Case [{self.current_case + 1}]:\n {header + self.fuzzing_cases[self.current_case].service.get_bytes()}")
      


    def monitor(self):
        """Send a monitor message and wait for answer to check if server is still alive

        :return True if it crashed false if not
        """
        read_property = BACnetService(0,12, [
            BACnetObject(0,1,4, b"\x02\x3f\xff\xff"),
            BACnetObject(1,1,1, b'\x4b')])
        
        resp = self.dl.send_and_get(read_property)
        if resp is None:
            fail(f"\tMonitor Failed : Timeout")
            return True
        if resp[0] == 0x81 and  resp[1] == 0xa and  resp[6] !=50:
            success(f"\tMonitor Suceed")
            return False
        fail(f"\tMonitor Failed : Error BACnet message")

        return True




    def fuzz(self,case):
        """ run a fuzzing case

        :param case the fuzzing case to run
        :retrun True if a crash is detected else false
        """
        result(f"\t{case.desc}")
        self.dl.send(case.service)
        time.sleep(0.1)
        
        return self.monitor()

    def fuzz_current(self):
        """Run the current fuzzing case and stop."""
        info(f"Running current fuzz case...")
        self.fuzz(self.fuzzing_cases[self.current_case])
        success(f"Execution finished.")

    def run_all(self):
        """Run all fuzzing cases from the current position until a crash occurs."""
        info(f"Running all fuzz cases until crash...")
        while self.current_case < len(self.fuzzing_cases):
            print(f"{Fore.MAGENTA}Running Case [{self.current_case + 1}]...{Style.RESET_ALL}")
            if self.fuzz(self.fuzzing_cases[self.current_case]):  # Assuming crash detection returns True
                fail(f"\tCrash detected at Case [{self.current_case + 1}]. Stopping.")
                return
            self.current_case += 1
        success(f"All fuzzing cases executed without crash.")

    def goto(self, index):
        """Move to the nth fuzzing case."""
        if 1 <= index <= len(self.fuzzing_cases):
            self.current_case = index - 1
            print(f"{Fore.BLUE}Moved to Case [{index}].{Style.RESET_ALL}")
        else:
            fail(f"Invalid index. Please enter a valid case number.")


