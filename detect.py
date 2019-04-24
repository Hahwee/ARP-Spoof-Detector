#!/usr/bin/env python
#Huy Le
#CMIT-140-45
#4/21/19

#needed libraries
import scapy.all as scapy
import subprocess
import optparse
import re
import time
import sys

#scans all IP addresses within the IP range provided in main() function
#function utilized from Udemy course here: https://www.udemy.com/learn-python-and-ethical-hacking-from-scratch/
def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    #displays list of IP addresses with MAC by uncommenting print statement below
    client_list = []
    for element in answered_list:
        client_Dic = {"ip" : element[1].psrc, "MAC" : element[1].hwsrc}
        client_list.append(client_Dic)
        #print(client_Dic["ip"] + " " + client_Dic["MAC"])
    return client_list

#if MAC address of default gateway is different, then notify of detection, if not, then continue scan as normal
#function modified from Udemy course: https://www.udemy.com/learn-python-and-ethical-hacking-from-scratch/
def detect(results_list):
	for client in results_list:
            if client["MAC"] != "replace this with default gateway MAC address":
                    print("ARP poisoning detected")
	    else:
                    print("Scanning")
                    

#constant value so program is recursive
i = 1

#program start and loop
try:
    while i == 1:
        #ifconfig_result = subprocess.check_output(["arp","-n"])
        #mac_address_search_result = re.search("(?<=\.18\))+\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", ifconfig_result)
        #print(mac_address_search_result.group(0))
	bleh = scan("replace with any IP address range in this format x*.x*.x*.0/24")
	detect(bleh)
        #time.sleep(1)

#end program with escape keys "control+c"
except KeyboardInterrupt:
        print("done")
