from scapy.all import *
from scapy.layers.http import HTTPResponse


def process_packet(packet):
    if packet.haslayer(HTTPResponse):
        httpData = packet[TCP].payload
        httpData = str(httpData)
        if '200' in httpData:
            htmlData = packet[HTTPResponse][Raw].load
            print(htmlData)
            
sniff(filter='port 80', prn=process_packet)
