from scapy.all import sniff, TCP, UDP, ICMP
from collections import Counter

def analyze_packet(packet, stats):
    if packet.haslayer(TCP):
        stats["TCP"] += 1
        if packet[TCP].dport == 80:
            stats["HTTP"] += 1
        elif packet[TCP].dport == 443:
            stats["HTTPS"] += 1

    elif packet.haslayer(UDP):
        stats["UDP"] += 1
        if packet[UDP].dport == 53:
            stats["DNS"] += 1

    elif packet.haslayer(ICMP):
        stats["ICMP"] += 1


def run_packet_monitor(duration=10):
    stats = Counter()

    print(f"\nMonitoring network traffic for {duration} seconds...\n")

    sniff(prn=lambda pkt: analyze_packet(pkt, stats), timeout=duration)

    return dict(stats)