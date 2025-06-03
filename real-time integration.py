from scapy.all import sniff, IP, TCP, UDP, ARP, Ether
import threading
import time
import csv

finished_flows = []
flows = []
packets = []  # Store packet metadata here
final_flows = []





def export_finished_flows_to_csv(filename="finished_flows.csv"):
    headers = [
        'src_ip', 'dst_ip', 'src_port', 'dst_port',  # Added headers
        'spkts', 'sbytes', 'dttl', 'dload', 'swin', 'synack', 'dmean',
        'ct_dst_sport_ltm', 'ct_srv_dst', 'proto_others', 'proto_arp', 'proto_udp',
        'service_dns', 'service_-', 'service_ftp', 'service_http', 'service_radius', 'service_smtp'
    ]

    with open(filename, mode='w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=headers)
        writer.writeheader()

        for flow in final_flows:
            # Calculate fields
            dload = 0
            duration = flow['Ltime'] - flow['stime'] if flow['Ltime'] and flow['stime'] and (flow['Ltime'] > flow['stime']) else 1
            if duration > 0:
                dload = (flow['dbytes'] * 8) / duration
            synack = 0
            if flow.get('syn_ack_time') and flow.get('syn_time'):
                synack = flow['syn_ack_time'] - flow['syn_time']
            dmean = 0
            if flow['dpkts'] > 0:
                dmean = flow['dbytes'] / flow['dpkts']

            # Protocol flags
            proto_arp = 1 if flow['protocol'] == 'ARP' else 0
            proto_udp = 1 if flow['protocol'] == 'UDP' else 0
            proto_others = 1 if flow['protocol'] not in ['ARP', 'UDP', 'TCP'] else 0

            # Service flags
            service_map = {
                'DNS': 'service_dns',
                '-': 'service_-',
                'FTP': 'service_ftp',
                'HTTP': 'service_http',
                'RADIUS': 'service_radius',
                'SMTP': 'service_smtp'
            }
            service_flags = {col: 0 for col in headers if col.startswith('service_')}
            svc = flow.get('service', '').upper()
            if svc == 'FTP-DATA':
                svc = 'FTP'
            for service_name, col_name in service_map.items():
                if svc == service_name:
                    service_flags[col_name] = 1
                    break
            if svc not in service_map.keys() and svc != '':
                service_flags['service_-'] = 1

            row = {
                'src_ip': flow.get('src_ip', ''),
                'dst_ip': flow.get('dst_ip', ''),
                'src_port': flow.get('src_port', ''),
                'dst_port': flow.get('dst_port', ''),
                'spkts': flow.get('spkts', 0),
                'sbytes': flow.get('sbytes', 0),
                'dttl': flow.get('dttl', ''),
                'dload': round(dload, 2),
                'swin': flow.get('swin', 0) if flow.get('swin') is not None else 0,
                'synack': round(synack, 6),
                'dmean': round(dmean, 2),
                'ct_dst_sport_ltm': flow.get('ct_dst_sport_ltm', 0),
                'ct_srv_dst': flow.get('ct_srv_dst', 0),
                'proto_others': proto_others,
                'proto_arp': proto_arp,
                'proto_udp': proto_udp,
                **service_flags
            }

            writer.writerow(row)

    print(f"Exported {len(final_flows)} finished flows to {filename}")






# Map port to service name
def get_service_name(port):
    service_map = {
        53: "DNS",
        67: "DHCP", 68: "DHCP",
        20: "FTP-DATA", 21: "FTP",
        80: "HTTP", 443: "HTTPS",
        194: "IRC",
        110: "POP3",
        1812: "RADIUS", 1813: "RADIUS",
        25: "SMTP",
        161: "SNMP", 162: "SNMP",
        22: "SSH"
    }
    return service_map.get(port, "Unknown")

# Bidirectional flow matching
def find_flow(src_ip, dst_ip, src_port, dst_port, protocol):
    for idx, flow in enumerate(flows):
        if (flow['src_ip'] == src_ip and flow['dst_ip'] == dst_ip and
            flow['src_port'] == src_port and flow['dst_port'] == dst_port and
            flow['protocol'] == protocol):
            return idx, 'forward'
        elif (flow['src_ip'] == dst_ip and flow['dst_ip'] == src_ip and
              flow['src_port'] == dst_port and flow['dst_port'] == src_port and
              flow['protocol'] == protocol):
            return idx, 'reverse'
    return None, None



#checking inactive flows
def check_inactive_flows():
    while True:
        current_time = time.time()
        inactive = [flow for flow in flows if current_time - flow['Ltime'] > 300]
        for flow in inactive:
            flows.remove(flow)
            finished_flows.append(flow)
            #print(f"[Inactive] Flow moved to finished_flows: {flow}")
            print('inactive flow added')
        time.sleep(50)




def update_ct_dst_sport_ltm():
    while True:
        # Copy the list to avoid modifying it while iterating
        flows_to_process = finished_flows[:]

        for flow in flows_to_process:
            flow_time = flow['Ltime']

            # Get last 100 packets before flow_time
            relevant_packets = [pkt for pkt in packets if pkt['ltime'] <= flow_time]
            relevant_packets = sorted(relevant_packets, key=lambda x: x['ltime'], reverse=True)[:100]

            # Count packets matching dst_ip and src_port
            ct_dst_sport_ltm = sum(
                1 for pkt in relevant_packets
                if pkt['dst_ip'] == flow['dst_ip'] and pkt['src_port'] == flow['src_port']
            )

            # Count packets matching dst_ip and service
            ct_srv_dst = sum(
                1 for pkt in relevant_packets
                if pkt['dst_ip'] == flow['dst_ip'] and pkt['service'] == flow['service']
            )

            # Update flow fields
            flow['ct_dst_sportS_ltm'] = ct_dst_sport_ltm
            flow['ct_srv_dst'] = ct_srv_dst

            print(f"[ct_dst_sport_ltm Updated] Flow: {flow['src_ip']}:{flow['src_port']} -> {flow['dst_ip']}:{flow['dst_port']} | Count: {ct_dst_sport_ltm}")
            print(f"[ct_srv_dst Updated] Flow: {flow['src_ip']}:{flow['src_port']} -> {flow['dst_ip']}:{flow['dst_port']} | Count: {ct_srv_dst}")

            # Remove flow from finished_flows and add to final_flows
            finished_flows.remove(flow)
            final_flows.append(flow)
            export_finished_flows_to_csv("finished_flow.csv")

        time.sleep(60)  # Wait before checking again






# Packet handler
def packet_callback(packet):
    current_time = packet.time
    pkt_len = len(packet)

    # Handle ARP
    if ARP in packet:
        protocol = "ARP"
        src_ip = packet[ARP].psrc
        dst_ip = packet[ARP].pdst
        src_port = dst_port = 0
        service = 'Unknown'

        packets.append({
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'service': service,
            'ltime': current_time
        })

        idx, direction = find_flow(src_ip, dst_ip, src_port, dst_port, protocol)
        if idx is not None:
            flow = flows[idx]
            if direction == 'forward':
                flow['spkts'] += 1
                flow['sbytes'] += pkt_len
            else:
                flow['dpkts'] += 1
                flow['dbytes'] += pkt_len
            flow['Ltime'] = current_time
            #print(f"[ARP] Updated flow: {flow}")
        else:
            new_flow = {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': 0,
                'dst_port': 0,
                'protocol': 'ARP',
                'service': 'Unknown',
                'spkts': 1,
                'dpkts': 0,
                'sttl': None,
                'dttl': None,
                'sbytes': pkt_len,
                'dbytes': 0,
                'stime': current_time,
                'Ltime': current_time,
                'swin': 0,
                'dwin': 0,
                'syn_time': None,
                'syn_ack_time': None,
                'ct_dst_sport_ltm': 0,
                'ct_srv_dst': 0
            }
            flows.append(new_flow)
            #print(f"[ARP] New flow created: {new_flow}")
        return

    # Handle IP packets
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        ttl = packet[IP].ttl
        proto = packet[IP].proto

        if proto == 6 and TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            tcp_flags = packet[TCP].flags
        elif proto == 17 and UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        else:
            protocol = "Others"
            src_port = dst_port = 0

        service = get_service_name(dst_port) if protocol in ['TCP', 'UDP'] else 'Unknown'

        # Save the packet info
        packets.append({
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'service': service,
            'ltime': current_time
        })

        idx, direction = find_flow(src_ip, dst_ip, src_port, dst_port, protocol)
        if idx is not None:
            flow = flows[idx]
            if direction == 'forward':
                flow['spkts'] += 1
                flow['sbytes'] += pkt_len
                if flow['sttl'] is None:
                    flow['sttl'] = ttl
                if protocol == 'TCP':
                    if flow['swin'] == 0:
                        flow['swin'] = packet[TCP].window
                    if tcp_flags == 'S':
                        flow['syn_time'] = current_time
            else:
                flow['dpkts'] += 1
                flow['dbytes'] += pkt_len
                if flow['dttl'] is None:
                    flow['dttl'] = ttl
                if protocol == 'TCP':
                    if flow['dwin'] == 0:
                        flow['dwin'] = packet[TCP].window
                    if tcp_flags == 'SA':
                        flow['syn_ack_time'] = current_time
            flow['Ltime'] = current_time
            #print(f"[{protocol}] Updated flow: {flow}")
        else:
            new_flow = {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': protocol,
                'service': service,
                'spkts': 1,
                'dpkts': 0,
                'sttl': ttl,
                'dttl': None,
                'sbytes': pkt_len,
                'dbytes': 0,
                'stime': current_time,
                'Ltime': current_time,
                'swin': packet[TCP].window if protocol == 'TCP' else 0,
                'dwin': 0,
                'syn_time': current_time if protocol == 'TCP' and TCP in packet and packet[TCP].flags == 'S' else None,
                'syn_ack_time': None,
                'ct_dst_sport_ltm': 0,
                'ct_srv_dst': 0
            }
            flows.append(new_flow)
            #print(f"[{protocol}] New flow created: {new_flow}")
        return

    # Handle Layer 2 packets (non-IP, non-ARP)
    if Ether in packet:
        src_ip = packet[Ether].src
        dst_ip = packet[Ether].dst
        protocol = "Others"
        src_port = dst_port = 0
        service = 'Unknown'

        packets.append({
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'service': service,
            'ltime': current_time
        })

        idx, direction = find_flow(src_ip, dst_ip, 0, 0, protocol)
        if idx is not None:
            flow = flows[idx]
            if direction == 'forward':
                flow['spkts'] += 1
                flow['sbytes'] += pkt_len
            else:
                flow['dpkts'] += 1
                flow['dbytes'] += pkt_len
            flow['Ltime'] = current_time
            #print(f"[Others] Updated Layer 2 flow: {flow}")
        else:
            new_flow = {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': 0,
                'dst_port': 0,
                'protocol': 'Others',
                'service': 'Unknown',
                'spkts': 1,
                'dpkts': 0,
                'sttl': None,
                'dttl': None,
                'sbytes': pkt_len,
                'dbytes': 0,
                'stime': current_time,
                'Ltime': current_time,
                'swin': None,
                'dwin': None,
                'syn_time': None,
                'syn_ack_time': None,
                'ct_dst_sport_ltm': 0,
                'ct_srv_dst': 0
            }
            flows.append(new_flow)
            #print(f"[Others] New Layer 2 flow created: {new_flow}")


            

   
checker_thread = threading.Thread(target=check_inactive_flows, daemon=True)
checker_thread.start()
ct_dst_sport_thread = threading.Thread(target=update_ct_dst_sport_ltm, daemon=True)
ct_dst_sport_thread.start()



# Start sniffing
print("Sniffing on Wi-Fi... Press Ctrl+C to stop.")
sniff(iface="Wi-Fi", prn=packet_callback)
