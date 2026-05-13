"""
parser.py — Extract structured data from raw Scapy packets
"""

from scapy.all import IP, TCP, UDP, ICMP, ARP, DNS, Raw


def parse_packet(packet):
    """
    Returns a dict with parsed fields from a Scapy packet.
    Returns None if not a recognised IP packet.
    """
    result = {
        'src_ip':    None,
        'dst_ip':    None,
        'protocol':  'OTHER',
        'src_port':  None,
        'dst_port':  None,
        'flags':     None,
        'size':      len(packet),
        'payload':   None,
        'is_syn':    False,
        'is_rst':    False,
        'is_fin':    False,
    }

    if ARP in packet:
        result['protocol'] = 'ARP'
        result['src_ip']   = packet[ARP].psrc
        result['dst_ip']   = packet[ARP].pdst
        return result

    if IP not in packet:
        return None

    result['src_ip'] = packet[IP].src
    result['dst_ip'] = packet[IP].dst

    if TCP in packet:
        result['protocol'] = 'TCP'
        result['src_port'] = packet[TCP].sport
        result['dst_port'] = packet[TCP].dport
        flags = packet[TCP].flags

        # Decode flags to human-readable
        flag_str = str(flags)
        result['flags']   = flag_str
        result['is_syn']  = 'S' in flag_str and 'A' not in flag_str
        result['is_rst']  = 'R' in flag_str
        result['is_fin']  = 'F' in flag_str

        if Raw in packet:
            try:
                result['payload'] = packet[Raw].load[:100].decode('utf-8', errors='replace')
            except Exception:
                pass

    elif UDP in packet:
        result['protocol'] = 'UDP'
        result['src_port'] = packet[UDP].sport
        result['dst_port'] = packet[UDP].dport

        if DNS in packet:
            result['protocol'] = 'DNS'
            try:
                result['payload'] = packet[DNS].qd.qname.decode() if packet[DNS].qd else None
            except Exception:
                pass

    elif ICMP in packet:
        result['protocol'] = 'ICMP'
        result['flags']    = str(packet[ICMP].type)

    return result