from scapy.all import *
from scapy.layers.http import HTTPResponse


def process_packet(packet):
    if packet.haslayer(HTTPResponse): # Check if packet is a HTTP Response
        httpData = packet[TCP].payload # Store HTTP information
        httpData = str(httpData) 
        if '200' in httpData: # Check if HTTP contains 200 OK Status
            htmlData = packet[HTTPResponse][Raw].load # Extract HTML information
            print(htmlData)
            
sniff(filter='port 80', prn=process_packet) # Sniff Packet with Port 80 (HTTP)
