import socket, sys
from struct import *

import time
import datetime

import os
import json
import requests

class Client:
    def __init__(self):
        with open("config.json", "r") as file:
            conf = json.load(file)

        self.delay = conf["delay"] # default : 5 Time to wait between packet detections in seconds
        self.noise = conf["noise"] # default : 200
        self.version = "0.0.1"
        self.location = conf["location"] # default : false
        
        self.ip = self.grab_ip()
        self.outHandeler = {str(i) : "" for i in range(self.noise)}
        self.tSP = {} # Time since packet

    def splash(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"""
███████╗███╗   ██╗██╗███████╗███████╗███████╗██████╗ 
██╔════╝████╗  ██║██║██╔════╝██╔════╝██╔════╝██╔══██╗
███████╗██╔██╗ ██║██║█████╗  █████╗  █████╗  ██████╔╝
╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗
███████║██║ ╚████║██║██║     ██║     ███████╗██║  ██║
╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝

  Your local UDP packet sniffer By Drillenissen#5308

Packet delay: {self.delay}s | Noise filter: {self.noise}
Script version: {self.version} | Source ip: {self.ip}

Press enter to start scanning""", end="", flush=True)
        
        input()

        self.listen()

    def packet_handeler(self, ip):
        """Noise filter, makes sure that it only accepts the packet if it was the same packet detected the last self.noise times"""
        contin = True

        # ==!==

        for i in range(self.noise -1, -1, -1): # Move each item back one in the dict
            self.outHandeler[str(i + 1)] = self.outHandeler[str(i)] 

        self.outHandeler["0"] = ip

        for indx, ip_addr in self.outHandeler.items():
            if ip_addr != ip:
                return False

        # ==!==

        try:
            if self.tSP[ip] + self.delay < time.time():
                self.tSP[ip] = time.time()
            else:
                contin = False
                
        except KeyError:
            self.tSP[ip] = time.time()

        # ==!==

        return contin

    def grab_ip(self):
        """Get the ip of the client, used as a filter"""
        p = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        p.connect(("8.8.8.8", 80))
        return p.getsockname()[0]

    def geolocate(self, ip):
        response = requests.get(f"https://ipapi.co/{ip}/json/") 

        if not response.ok:
            return "Not avaliable"
        try: # If there is a key named error it must not have gone though
            response.json()["error"]
            return "API Error"
        except KeyError:
            pass

        jsonResp = response.json()

        out = "\n"
        out += f"Country: {jsonResp['country_name']}\n"
        out += f"Region: {jsonResp['region']}\n"
        out += f"City: {jsonResp['city']}\n"

        return out

    def listen(self):
        """Listen for outgoing UDP requests"""
        # Listing code is based off of https://github.com/ShyamsundarDas/packet-sniffers-in-python-using-raw-sockets/blob/master/packetcapture.py
        # Lets not reinvent the wheel ;)
        s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))

        print("Started scanning for UDP packets\n")

        while True:
            packet = s.recvfrom(65565)[0]

            eth_length = 14
            header = packet[:eth_length] 
            eth = unpack('!6s6sH', header)
            eth_protocol = socket.ntohs(eth[2])

            if eth_protocol == 8:
                ip_header = packet[eth_length:20+eth_length]
                iph = unpack('!BBHHHBBH4s4s' , ip_header)

                protocol = iph[6]
                s_addr = socket.inet_ntoa(iph[8]);
                d_addr = socket.inet_ntoa(iph[9]);

                if protocol == 17 and s_addr == self.ip and self.packet_handeler(d_addr):
                    print(f"{'='*50}\nOUTGOING UDP PACKET\nDestination: {d_addr:<15} Time: {datetime.datetime.now()}")

                    if self.location:
                        print(self.geolocate(d_addr))

                    print(f"{'='*50}\n")
                    

if __name__ == "__main__":
    Client().splash()
