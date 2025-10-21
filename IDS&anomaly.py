from scapy.all import *
import time
import csv

def process_packet(pkt, csv_writer, csv_file):
    """
    Invoked everytime a packet is detected
    Args:
        pkt: detected packet
    """
    global ip_mac_map, alerted_ips, traffic_tracker, syn_tracker
    is_alert = 0
    timestamp = time.time()
    if pkt.haslayer(ARP):   # type: ignore
        # ARP SPOOF DETECTOR
        if pkt[ARP].op == 2:
            sip = pkt[ARP].psrc
            smac = pkt[ARP].hwsrc
            if sip not in ip_mac_map:
                ip_mac_map[sip] = smac
            else:
                if smac != ip_mac_map[sip]:
                    print(f"ALERT: ARP spoof detected from source IP: {sip}")
                    is_alert = 1
            
            dip = pkt[ARP].pdst
            row = [timestamp, sip, dip, -1, -1, 'ARP', len(pkt), '', is_alert]
            csv_writer.writerow(row)
            csv_file.flush()
        return
    
    if pkt.haslayer(IP):
        flags = ''
        protocol = pkt[IP].proto
        sport, dport = -1, -1
        src = pkt[IP].src
        dst = pkt[IP].dst

        # TRAFFIC BURST DETECTOR
        pkt_len = len(pkt)
        # print(f"IP Packet: {src} -> {dst}")
        if src in traffic_tracker:
            traffic_tracker[src]["byte_count"] += pkt_len
            curr_time = time.time()
            time_passed = curr_time - traffic_tracker[src]["timestamp"]
            if time_passed >= 2:
                if traffic_tracker[src]["byte_count"] >= 1000000:
                    print(f"ALERT: Traffic burst detected from IP address: {src}")
                    is_alert = 1
                traffic_tracker[src]["timestamp"] = curr_time
                traffic_tracker[src]["byte_count"] = 0
        else:
            traffic_tracker[src] = {"byte_count": pkt_len,
                                    "timestamp" : time.time()}

        if pkt.haslayer(TCP):
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            # print(f"TCP/IP Packet: src: {src} | dst: {dst} | sport: {sport} | dport: {dport}")

            # PORT SCAN DETECTOR
            if src in ip_port_map:
                ip_port_map[src].add(dport)
            else:
                ip_port_map[src] = {dport}

            if len(ip_port_map[src]) > 20 and src not in alerted_ips:
                print(f"ALERT: Port scan detected from IP address: {src}")
                is_alert = 1
                alerted_ips.add(src)

            # TCP SYN FLOOD DETECTOR
            if pkt[TCP].flags == 'S':
                flags = 'S'
                if src not in syn_tracker:
                    syn_tracker[src] = {'count': 0, 'timestamp': time.time()}
                syn_tracker[src]["count"] += 1

                passed_time = time.time() - syn_tracker[src]['timestamp']
                if passed_time >= 5:
                    if syn_tracker[src]['count'] >= 30:
                        print(f"ALERT: SYN flood detected from IP address: {src}")
                        is_alert = 1
                    syn_tracker[src]['count'] = 0
                    syn_tracker[src]['timestamp'] = time.time()
    
        row = [timestamp, src, dst, sport, dport, protocol, len(pkt), flags, is_alert]
        csv_writer.writerow(row)
        csv_file.flush()
        return
    

print('Starting sniffer')

# For port scan detector
ip_port_map = dict()    # {src: [dst]}
alerted_ips = set()

# For Traffic Burst detector
traffic_tracker = dict()    # {src: {'byte_count': X, 'timestamp': Y}}

# For ARP spoof detector
ip_mac_map = dict()

# For TCP SYN flood detector
syn_tracker = dict()    # {'ip': {'count': X, 'timestamp': Y}}

# Logging packets
header = ['timestamp', 'source_ip', 'destination_ip', 'source_port', 'destination_port', 'protocol', 'length', 'flags', 'rule_based_alert']

try:
    with open('network_traffic.csv', 'w', newline='') as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(header)

        print("Sniffer starting... Press Ctrl+C to stop.")

        sniff(prn=lambda pkt: process_packet(pkt, csv_writer, csv_file), store=0)

except KeyboardInterrupt:
    print("\nSniffer stopped by user. CSV file saved.")
except Exception as e:
    print(f"An error occurred: {e}")