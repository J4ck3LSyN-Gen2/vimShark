#!/usr/bin/env python3
import sys, os, time, threading, queue, re, subprocess, argparse
from collections import deque, defaultdict

try:
    from scapy.all import sniff, Ether, IP, IPv6, TCP, UDP, ARP, DNS, ICMP, NTP, Raw, srp, conf, PcapWriter
except ImportError:
    print("[!] Scapy is required: pip install scapy");sys.exit(1)

# Ensure HTTP and TLS layers are loaded for dissection
try:
    from scapy.all import load_layer
    load_layer("http")
    load_layer("tls")
    load_layer("ntp")
except: pass

try: import urwid
except ImportError:
    print("[!] Urwid is required: pip install urwid");sys.exit(1)

__verion__ = "0.1.6"
__author__ = "J4ck3LSyN"
__all__ = ["vimSharkApp"]


# ==============================================================================
# THEMES

THEMES = {
    "btop_classic": [
        ('bg', 'default', 'default', 'default', '#ffffff', '#0f1419'),
        ('header', 'white', 'dark blue', 'bold', '#ffffff', '#005f87'),
        ('footer', 'light gray', 'black', None, '#aaaaaa', '#121820'),
        ('border', 'dark gray', 'default', 'default', '#3a4454', '#0f1419'),
        ('selected', 'black', 'light green', 'standout', '#0f1419', '#00ff87'),
        ('pkt_tcp', 'light blue', 'default', 'default', '#00afff', '#0f1419'),
        ('pkt_udp', 'light magenta', 'default', 'default', '#d700ff', '#0f1419'),
        ('pkt_arp', 'yellow', 'default', 'default', '#ffaf00', '#0f1419'),
        ('pkt_dns', 'light cyan', 'default', 'default', '#00ffd7', '#0f1419'),
        ('pkt_icmp', 'light red', 'default', 'default', '#ff5555', '#0f1419'),
        ('pkt_http', 'dark green', 'default', 'default', '#00af5f', '#0f1419'),
        ('pkt_tls', 'light blue', 'default', 'default', '#5fafff', '#0f1419'),
        ('pkt_ntp', 'yellow', 'default', 'default', '#ffaf00', '#0f1419'),
        ('pkt_other', 'light gray', 'default', 'default', '#8a95a5', '#0f1419'),
        ('telemetry_label', 'white', 'default', 'bold', '#00ff87', '#0f1419'),
        ('spark_bar', 'light green', 'default', None, '#00ff87', '#0f1419'),
        ('mitm_active', 'light red', 'default', 'blink', '#ff3333', '#0f1419'),
        ('mitm_safe', 'light green', 'default', None, '#00ff87', '#0f1419'),
        ('alert_high', 'white', 'dark red', 'blink', '#ffffff', '#d70000'),
        ('text_focus', 'white', 'dark cyan', None, '#ffffff', '#0087af'),
    ],
    "gruvbox_dark": [
        ('bg', 'default', 'default', 'default', '#ebdbb2', '#282828'),
        ('header', 'black', 'yellow', 'bold', '#282828', '#fabd2f'),
        ('footer', 'dark gray', 'black', None, '#928374', '#1d2021'),
        ('border', 'brown', 'default', 'default', '#504945', '#282828'),
        ('selected', 'black', 'light green', 'standout', '#282828', '#b8bb26'),
        ('pkt_tcp', 'light blue', 'default', 'default', '#83a598', '#282828'),
        ('pkt_udp', 'light magenta', 'default', 'default', '#d3869b', '#282828'),
        ('pkt_arp', 'yellow', 'default', 'default', '#fe8019', '#282828'),
        ('pkt_dns', 'light cyan', 'default', 'default', '#8ec07c', '#282828'),
        ('pkt_icmp', 'light red', 'default', 'default', '#fb4934', '#282828'),
        ('pkt_http', 'dark green', 'default', 'default', '#b8bb26', '#282828'),
        ('pkt_tls', 'light blue', 'default', 'default', '#83a598', '#282828'),
        ('pkt_ntp', 'yellow', 'default', 'default', '#fe8019', '#282828'),
        ('pkt_other', 'light gray', 'default', 'default', '#a89984', '#282828'),
        ('telemetry_label', 'yellow', 'default', 'bold', '#fabd2f', '#282828'),
        ('spark_bar', 'light green', 'default', None, '#b8bb26', '#282828'),
        ('mitm_active', 'light red', 'default', 'blink', '#fb4934', '#282828'),
        ('mitm_safe', 'light green', 'default', None, '#b8bb26', '#282828'),
        ('alert_high', 'white', 'dark red', 'blink', '#ffffff', '#cc241d'),
        ('text_focus', 'white', 'dark blue', None, '#ffffff', '#458588'),
    ],
    "dracula": [
        ('bg', 'default', 'default', 'default', '#f8f8f2', '#282a36'),
        ('header', 'white', 'light magenta', 'bold', '#f8f8f2', '#bd93f9'),
        ('footer', 'light gray', 'black', None, '#6272a4', '#1e1f29'),
        ('border', 'light magenta', 'default', 'default', '#44475a', '#282a36'),
        ('selected', 'black', 'light green', 'standout', '#282a36', '#50fa7b'),
        ('pkt_tcp', 'light blue', 'default', 'default', '#8be9fd', '#282a36'),
        ('pkt_udp', 'light magenta', 'default', 'default', '#ff79c6', '#282a36'),
        ('pkt_arp', 'yellow', 'default', 'default', '#ffb86c', '#282a36'),
        ('pkt_dns', 'light cyan', 'default', 'default', '#a4ffff', '#282a36'),
        ('pkt_icmp', 'light red', 'default', 'default', '#ff5555', '#282a36'),
        ('pkt_http', 'dark green', 'default', 'default', '#50fa7b', '#282a36'),
        ('pkt_tls', 'light blue', 'default', 'default', '#8be9fd', '#282a36'),
        ('pkt_ntp', 'yellow', 'default', 'default', '#ffb86c', '#282a36'),
        ('pkt_other', 'light gray', 'default', 'default', '#f8f8f2', '#282a36'),
        ('telemetry_label', 'light magenta', 'default', 'bold', '#ff79c6', '#282a36'),
        ('spark_bar', 'light green', 'default', None, '#50fa7b', '#282a36'),
        ('mitm_active', 'light red', 'default', 'blink', '#ff5555', '#282a36'),
        ('mitm_safe', 'light green', 'default', None, '#50fa7b', '#282a36'),
        ('alert_high', 'white', 'dark red', 'blink', '#ffffff', '#ff5555'),
        ('text_focus', 'white', 'dark magenta', None, '#ffffff', '#bd93f9'),
    ],
    "nord": [
        ('bg', 'default', 'default', 'default', '#d8dee9', '#2e3440'),
        ('header', 'white', 'dark blue', 'bold', '#eceff4', '#5e81ac'),
        ('footer', 'dark gray', 'black', None, '#4c566a', '#3b4252'),
        ('border', 'light gray', 'default', 'default', '#434c5e', '#2e3440'),
        ('selected', 'black', 'light cyan', 'standout', '#2e3440', '#88c0d0'),
        ('pkt_tcp', 'light blue', 'default', 'default', '#81a1c1', '#2e3440'),
        ('pkt_udp', 'light magenta', 'default', 'default', '#b48ead', '#2e3440'),
        ('pkt_arp', 'yellow', 'default', 'default', '#ebcb8b', '#2e3440'),
        ('pkt_dns', 'light cyan', 'default', 'default', '#8fbcbb', '#2e3440'),
        ('pkt_icmp', 'light red', 'default', 'default', '#bf616a', '#2e3440'),
        ('pkt_http', 'dark green', 'default', 'default', '#a3be8c', '#2e3440'),
        ('pkt_tls', 'light blue', 'default', 'default', '#88c0d0', '#2e3440'),
        ('pkt_ntp', 'yellow', 'default', 'default', '#ebcb8b', '#2e3440'),
        ('pkt_other', 'white', 'default', 'default', '#d8dee9', '#2e3440'),
        ('telemetry_label', 'light cyan', 'default', 'bold', '#88c0d0', '#2e3440'),
        ('spark_bar', 'light green', 'default', None, '#a3be8c', '#2e3440'),
        ('mitm_active', 'light red', 'default', 'blink', '#bf616a', '#2e3440'),
        ('mitm_safe', 'light green', 'default', None, '#a3be8c', '#2e3440'),
        ('alert_high', 'white', 'dark red', 'blink', '#ffffff', '#bf616a'),
        ('text_focus', 'white', 'dark blue', None, '#ffffff', '#81a1c1'),
    ],
    "monokai": [
        ('bg', 'default', 'default', 'default', '#f8f8f2', '#272822'),
        ('header', 'black', 'light red', 'bold', '#272822', '#f92672'),
        ('footer', 'dark gray', 'black', None, '#75715e', '#1e1e1e'),
        ('border', 'dark gray', 'default', 'default', '#49483e', '#272822'),
        ('selected', 'black', 'light green', 'standout', '#272822', '#a6e22e'),
        ('pkt_tcp', 'light blue', 'default', 'default', '#66d9ef', '#272822'),
        ('pkt_udp', 'light magenta', 'default', 'default', '#ae81ff', '#272822'),
        ('pkt_arp', 'yellow', 'default', 'default', '#e6db74', '#272822'),
        ('pkt_dns', 'light green', 'default', 'default', '#a6e22e', '#272822'),
        ('pkt_icmp', 'light red', 'default', 'default', '#f92672', '#272822'),
        ('pkt_http', 'dark green', 'default', 'default', '#a6e22e', '#272822'),
        ('pkt_tls', 'light blue', 'default', 'default', '#66d9ef', '#272822'),
        ('pkt_ntp', 'yellow', 'default', 'default', '#e6db74', '#272822'),
        ('pkt_other', 'white', 'default', 'default', '#f8f8f2', '#272822'),
        ('telemetry_label', 'light red', 'default', 'bold', '#f92672', '#272822'),
        ('spark_bar', 'light green', 'default', None, '#a6e22e', '#272822'),
        ('mitm_active', 'light red', 'default', 'blink', '#f92672', '#272822'),
        ('mitm_safe', 'light green', 'default', None, '#a6e22e', '#272822'),
        ('alert_high', 'white', 'dark red', 'blink', '#ffffff', '#f92672'),
        ('text_focus', 'white', 'light magenta', None, '#ffffff', '#ae81ff'),
    ],
    "solarized_dark": [
        ('bg', 'default', 'default', 'default', '#839496', '#002b36'),
        ('header', 'white', 'dark blue', 'bold', '#fdf6e3', '#268bd2'),
        ('footer', 'dark gray', 'black', None, '#586e75', '#073642'),
        ('border', 'dark gray', 'default', 'default', '#586e75', '#002b36'),
        ('selected', 'black', 'light green', 'standout', '#002b36', '#859900'),
        ('pkt_tcp', 'light blue', 'default', 'default', '#268bd2', '#002b36'),
        ('pkt_udp', 'light magenta', 'default', 'default', '#d33682', '#002b36'),
        ('pkt_arp', 'yellow', 'default', 'default', '#b58900', '#002b36'),
        ('pkt_dns', 'light cyan', 'default', 'default', '#2aa198', '#002b36'),
        ('pkt_icmp', 'light red', 'default', 'default', '#dc322f', '#002b36'),
        ('pkt_http', 'dark green', 'default', 'default', '#859900', '#002b36'),
        ('pkt_tls', 'light blue', 'default', 'default', '#268bd2', '#002b36'),
        ('pkt_ntp', 'yellow', 'default', 'default', '#b58900', '#002b36'),
        ('pkt_other', 'light gray', 'default', 'default', '#839496', '#002b36'),
        ('telemetry_label', 'yellow', 'default', 'bold', '#b58900', '#002b36'),
        ('spark_bar', 'light green', 'default', None, '#859900', '#002b36'),
        ('mitm_active', 'light red', 'default', 'blink', '#dc322f', '#002b36'),
        ('mitm_safe', 'light green', 'default', None, '#859900', '#002b36'),
        ('alert_high', 'white', 'dark red', 'blink', '#ffffff', '#dc322f'),
        ('text_focus', 'white', 'dark cyan', None, '#ffffff', '#2aa198'),
    ],
    "cyberpunk": [
        ('bg', 'default', 'default', 'default', '#00ff00', '#000b1e'),
        ('header', 'white', 'dark magenta', 'bold', '#ffffff', '#ff0055'),
        ('footer', 'dark gray', 'black', None, '#00ffff', '#001a33'),
        ('border', 'dark magenta', 'default', 'default', '#ff0055', '#000b1e'),
        ('selected', 'black', 'light green', 'standout', '#000b1e', '#00ff00'),
        ('pkt_tcp', 'light blue', 'default', 'default', '#00afff', '#000b1e'),
        ('pkt_udp', 'light magenta', 'default', 'default', '#ff00ff', '#000b1e'),
        ('pkt_arp', 'yellow', 'default', 'default', '#ffff00', '#000b1e'),
        ('pkt_dns', 'light cyan', 'default', 'default', '#00ffff', '#000b1e'),
        ('pkt_icmp', 'light red', 'default', 'default', '#ff0000', '#000b1e'),
        ('pkt_http', 'dark green', 'default', 'default', '#00ff00', '#000b1e'),
        ('pkt_tls', 'light blue', 'default', 'default', '#00ffff', '#000b1e'),
        ('pkt_ntp', 'yellow', 'default', 'default', '#ffff00', '#000b1e'),
        ('pkt_other', 'white', 'default', 'default', '#00ff00', '#000b1e'),
        ('telemetry_label', 'light magenta', 'default', 'bold', '#ff00ff', '#000b1e'),
        ('spark_bar', 'light green', 'default', None, '#00ff00', '#000b1e'),
        ('mitm_active', 'light red', 'default', 'blink', '#ff0000', '#000b1e'),
        ('mitm_safe', 'light green', 'default', None, '#00ff00', '#000b1e'),
        ('alert_high', 'white', 'dark red', 'blink', '#ffffff', '#ff0000'),
        ('text_focus', 'black', 'light cyan', None, '#000000', '#00ffff'),
    ]
}

# ==============================================================================
# TELEMETRY
# ==============================================================================
class TrafficTelemetry:
    def __init__(self, max_history=50):
        self.max_history = max_history
        self.packet_history = deque([0] * max_history, maxlen=max_history)
        self.byte_history = deque([0] * max_history, maxlen=max_history)
        self.packet_accumulator = 0
        self.byte_accumulator = 0
        self.last_update_time = time.time()
        self.unicode_blocks = '▁▂▃▄▅▆▇█'

    def accumulate(self, packet_len):
        self.packet_accumulator += 1
        self.byte_accumulator += packet_len

    def tick(self):
        elapsed = time.time() - self.last_update_time
        if elapsed < 0.1:
            elapsed = 1.0

        p_rate = int(self.packet_accumulator / elapsed)
        b_rate = int(self.byte_accumulator / elapsed)

        self.packet_history.append(p_rate)
        self.byte_history.append(b_rate)

        self.packet_accumulator = 0
        self.byte_accumulator = 0
        self.last_update_time = time.time()
        return p_rate, b_rate

    def generate_sparkline(self, metric="packets"):
        history = list(self.packet_history if metric == "packets" else self.byte_history)
        if not history or max(history) == 0:
            return "▁" * len(history)
        h_min, h_max = min(history), max(history)
        delta = h_max - h_min
        return "".join(self.unicode_blocks[int((v - h_min) * 7 / delta)] for v in history)


# ==============================================================================
# DISSECTOR
# ==============================================================================
class DetailedDissector:
    def __init__(self):
        self.tcp_flows = defaultdict(list)  # flow_key -> list of payloads

    @staticmethod
    def dissect_to_dict(packet):
        summary = {"protocol": "OTHER", "src": "N/A", "dst": "N/A", "len": len(packet), "summary": packet.summary()}

        try:
            if Ether in packet:
                summary["eth_src"] = packet[Ether].src
                summary["eth_dst"] = packet[Ether].dst

            if IP in packet:
                summary["src"] = packet[IP].src
                summary["dst"] = packet[IP].dst
                summary["protocol"] = "IP"
            elif IPv6 in packet:
                summary["src"] = packet[IPv6].src
                summary["dst"] = packet[IPv6].dst
                summary["protocol"] = "IPv6"

            if ARP in packet:
                summary["src"] = packet.psrc
                summary["dst"] = packet.pdst
                summary["protocol"] = "ARP"
                op = "request" if packet.op == 1 else "is-at"
                summary["summary"] = f"ARP {op} {packet.psrc} → {packet.hwsrc}"

            if TCP in packet:
                if summary["src"] != "N/A":
                    summary["src"] = f"{summary['src']}:{packet[TCP].sport}"
                    summary["dst"] = f"{summary['dst']}:{packet[TCP].dport}"
                else:
                    summary["src"], summary["dst"] = str(packet[TCP].sport), str(packet[TCP].dport)
                summary["protocol"] = "TCP"
                if DNS in packet:
                    summary["protocol"] = "DNS"
                    qtype = "Query" if packet[DNS].qr == 0 else "Response"
                    summary["summary"] = f"DNS {qtype} ID={packet[DNS].id}"
                elif packet.haslayer("HTTP") or packet.haslayer("HTTPRequest") or packet.haslayer("HTTPResponse"):
                    summary["protocol"] = "HTTP"
                    summary["summary"] = f"HTTP Traffic: {packet.summary()}"
                elif packet.haslayer("TLS") or packet.haslayer("SSL") or packet[TCP].sport == 443 or packet[TCP].dport == 443:
                    summary["protocol"] = "TLS"
                    summary["summary"] = "TLS/SSL Encrypted Data"
                else:
                    flags = packet.sprintf("%TCP.flags%")
                    summary["summary"] = f"TCP {packet[TCP].sport}→{packet[TCP].dport} [{flags}] Seq={packet[TCP].seq}"

            elif UDP in packet:
                if summary["src"] != "N/A":
                    summary["src"] = f"{summary['src']}:{packet[UDP].sport}"
                    summary["dst"] = f"{summary['dst']}:{packet[UDP].dport}"
                else:
                    summary["src"], summary["dst"] = str(packet[UDP].sport), str(packet[UDP].dport)
                summary["protocol"] = "UDP"
                if DNS in packet:
                    summary["protocol"] = "DNS"
                    qtype = "Query" if packet[DNS].qr == 0 else "Response"
                    summary["summary"] = f"DNS {qtype} ID={packet[DNS].id}"
                elif NTP in packet:
                    summary["protocol"] = "NTP"
                    summary["summary"] = f"NTP v{packet[NTP].version} Mode {packet[NTP].mode} Stratum {packet[NTP].stratum}"
            elif ICMP in packet:
                summary["protocol"] = "ICMP"
                summary["summary"] = f"ICMP Type={packet[ICMP].type} Code={packet[ICMP].code}"
            elif packet.haslayer("ICMPv6"):
                summary["protocol"] = "ICMP"
                summary["summary"] = f"ICMPv6 {packet.summary()}"
        except Exception: pass  # Graceful fallback
        return summary

    def parse_payloads_to_string(self, packet):
        if Raw not in packet:
            return ""
        payload = packet[Raw].load
        cred_keywords = [b"user", b"pass", b"secret", b"auth", b"login", b"password"]
        alerts = []
        for word in cred_keywords:
            if word in payload.lower():
                alerts.append(f"[*] CREDENTIAL LEAK: '{word.decode(errors='ignore')}'")
        try:
            text = payload.decode('utf-8', errors='ignore')
            return "\n".join(alerts) + ("\n" + text if text.strip() else "")
        except: return "\n".join(alerts)

    @staticmethod
    def generate_hexdump(data_bytes):
        lines = []
        for i in range(0, len(data_bytes), 16):
            chunk = data_bytes[i:i+16]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            lines.append(f"{i:04x}  {hex_part:<47}  {ascii_part}")
        return "\n".join(lines)

    def track_tcp_flow(self, packet):
        if IP in packet and TCP in packet and Raw in packet:
            flow_key = frozenset({
                (packet[IP].src, packet[TCP].sport),
                (packet[IP].dst, packet[TCP].dport)
            })
            self.tcp_flows[flow_key].append(packet[Raw].load)

    def get_flow_data(self, packet):
        if IP not in packet or TCP not in packet:
            return b""
        flow_key = frozenset({
            (packet[IP].src, packet[TCP].sport),
            (packet[IP].dst, packet[TCP].dport)
        })
        return b"".join(self.tcp_flows.get(flow_key, []))


# ==============================================================================
# THREAT AUDITOR
# ==============================================================================
class ThreatAuditor:
    def __init__(self, alert_callback):
        self.alert_callback = alert_callback
        self.arp_table = {}
        self.alert_history = set()

    def load_initial_system_arp_cache(self):
        try:
            if os.path.exists("/proc/net/arp"):
                with open("/proc/net/arp") as f:
                    for line in f.readlines()[1:]:
                        parts = line.split()
                        if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
                            self.arp_table[parts[0]] = parts[3].lower()
            else:
                # Windows / other
                res = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5)
                for match in re.finditer(r"(\d+\.\d+\.\d+\.\d+).*?([0-9a-fA-F:-]{17})", res.stdout):
                    self.arp_table[match.group(1)] = match.group(2).lower()
        except Exception as e:
            self.alert_callback(f"ARP cache load failed: {e}")

    def passive_arp_sniff_hook(self, packet):
        if ARP in packet and packet.op == 2:  # is-at
            ip = packet.psrc
            mac = packet.hwsrc.lower()
            if ip in self.arp_table and self.arp_table[ip] != mac:
                key = (ip, self.arp_table[ip], mac)
                if key not in self.alert_history:
                    self.alert_history.add(key)
                    self.alert_callback(f"ARP SPOOF DETECTED! {ip} changed from {self.arp_table[ip]} to {mac}")
            else:
                self.arp_table[ip] = mac

    def trigger_active_validation(self, ip, iface):
        self.alert_callback(f"[*] Probing {ip} on {iface}...")
        try:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=3, iface=iface, verbose=0)
            if len(ans) > 1:
                macs = {rcv.hwsrc for _, rcv in ans}
                self.alert_callback(f"[!!!] MULTIPLE MACs for {ip}: {macs}")
            elif ans:
                _, rcv = ans[0]
                self.alert_callback(f"[+] {ip} → {rcv.hwsrc}")
            else:
                self.alert_callback(f"[!] No response from {ip}")
        except Exception as e:
            self.alert_callback(f"Probe failed: {e}")


# ==============================================================================
# MAIN APP
# ==============================================================================
class vimSharkApp:
    def __init__(self, interface="eth0", pcap_file=None, output_file=None):
        self.interface = interface
        self.pcap_file = pcap_file
        self.output_file = output_file
        self.telemetry = TrafficTelemetry()
        self.dissector = DetailedDissector()
        self.auditor = ThreatAuditor(self.queue_alert)

        self.pcap_writer = None
        if self.output_file:
            self.pcap_writer = PcapWriter(self.output_file, append=True, sync=True)

        self.pkt_queue = queue.Queue(maxsize=500)
        self.alert_queue = queue.Queue()
        self.is_running = True
        self.capture_paused = False
        self.all_packets = []  # Stores (summary, raw_pkt, idx)
        self.display_filter = ""

        self.packet_count = 0
        self.current_theme = "btop_classic"
        self.selected_index = None

        self.setup_ui()
        self.auditor.load_initial_system_arp_cache()

    def setup_ui(self):
        # Header
        source = self.pcap_file if self.pcap_file else self.interface
        self.header = urwid.Text(f" vimShark | {source} | Packets: 0 | Theme: {self.current_theme}")
        self.header_widget = urwid.AttrMap(self.header, 'header')

        # Filter Bar
        self.filter_edit = urwid.Edit(" Filter: ")
        urwid.connect_signal(self.filter_edit, 'change', self.on_filter_change)
        self.filter_bar = urwid.AttrMap(self.filter_edit, 'bg', 'text_focus')

        # Packet list
        self.walker = urwid.SimpleFocusListWalker([])
        self.packet_list = urwid.ListBox(self.walker)
        
        self.list_container = urwid.Pile([
            ('pack', self.filter_bar),
            ('weight', 1, urwid.AttrMap(self.packet_list, 'bg'))
        ])
        self.left_top = urwid.AttrMap(urwid.LineBox(self.list_container, title="Live Capture"), 'border')

        # Telemetry
        self.rate_pkt = urwid.Text("Packet Rate: 0 p/s")
        self.rate_byte = urwid.Text("Data Rate:   0 B/s")
        self.telemetry_pile = urwid.Pile([self.rate_pkt, self.rate_byte])
        self.telemetry_filler = urwid.Filler(self.telemetry_pile, valign='top')
        self.left_bottom = urwid.AttrMap(urwid.LineBox(urwid.AttrMap(self.telemetry_filler, 'bg'), title="Telemetry"), 'border')

        self.left_pane = urwid.Pile([('weight', 5, self.left_top), ('weight', 1, self.left_bottom)])

        # Right pane
        self.details_walker = urwid.SimpleFocusListWalker([urwid.Text("Select a packet...")])
        self.details_box = urwid.AttrMap(urwid.LineBox(urwid.AttrMap(urwid.ListBox(self.details_walker), 'bg'), title="Packet Details"), 'border')

        self.hex_walker = urwid.SimpleFocusListWalker([urwid.Text("Hex dump...")])
        self.hex_box = urwid.AttrMap(urwid.LineBox(urwid.AttrMap(urwid.ListBox(self.hex_walker), 'bg'), title="Hex Dump"), 'border')

        self.alert_walker = urwid.SimpleFocusListWalker([])
        self.alert_box = urwid.AttrMap(urwid.LineBox(urwid.AttrMap(urwid.ListBox(self.alert_walker), 'bg'), title="Threat Alerts"), 'border')

        right_pane = urwid.Pile([
            ('weight', 3, self.details_box),
            ('weight', 2, self.hex_box),
            ('weight', 2, self.alert_box)
        ])

        self.body = urwid.Columns([('weight', 3, self.left_pane), ('weight', 2, right_pane)], dividechars=1)
        self.footer = urwid.Text(" [Q] Quit | [T] Theme | [/] Search | [P] Pause | [F] Follow | [C] Clear | [V] Validate | Arrows/Enter")
        self.main_frame = urwid.Frame(
            body=urwid.AttrMap(self.body, 'bg'),
            header=self.header_widget,
            footer=urwid.AttrMap(self.footer, 'footer')
        )
        self.root = urwid.AttrMap(self.main_frame, 'bg')

    def queue_alert(self, msg): self.alert_queue.put(msg)

    def update_theme(self):
        themes = list(THEMES.keys())
        idx = (themes.index(self.current_theme) + 1) % len(themes)
        self.current_theme = themes[idx]
        palette = THEMES[self.current_theme]
        self.loop.screen.register_palette(palette)
        self.loop.screen.clear()
        if self.loop: self.loop.draw_screen()
        self.header.set_text(f" vimShark | {self.interface} | Packets: {self.packet_count} | Theme: {self.current_theme}")

    def on_filter_change(self, widget, new_text):
        self.display_filter = new_text
        self.refresh_display()

    def refresh_display(self):
        self.walker.clear()
        for summary, pkt, idx in self.all_packets:
            if self.matches_filter(summary, pkt, self.display_filter): self._add_to_walker(summary, pkt, idx)

    def matches_filter(self, summary, pkt, filter_str):
        if not filter_str.strip(): return True
        try:
            # Evaluate OR clauses (||)
            or_clauses = [c.strip() for c in filter_str.split('||')]
            for clause in or_clauses:
                if not clause: continue
                
                # Evaluate AND parts (&&) within the clause
                and_parts = [p.strip() for p in clause.split('&&')]
                clause_match = True
                for part in and_parts:
                    if '==' not in part: continue
                    field, val = [i.strip() for i in part.split('==', 1)]
                    
                    if field == 'type' and summary['protocol'].lower() != val.lower():
                        clause_match = False; break
                    elif field == 'ip.src' and not ((IP in pkt and pkt[IP].src == val) or (IPv6 in pkt and pkt[IPv6].src == val)):
                        clause_match = False; break
                    elif field == 'ip.dst' and not ((IP in pkt and pkt[IP].dst == val) or (IPv6 in pkt and pkt[IPv6].dst == val)):
                        clause_match = False; break
                    elif field == 'in_data' and val.lower() not in bytes(pkt).hex().lower():
                        clause_match = False; break
                if clause_match: return True
            return False
        except: return False

    def add_packet(self, summary, raw_pkt):
        self.packet_count += 1
        idx = self.packet_count
        self.all_packets.append((summary, raw_pkt, idx))
        if len(self.all_packets) > 1000: self.all_packets.pop(0)
        if self.capture_paused: return
        if self.matches_filter(summary, raw_pkt, self.display_filter):
            self._add_to_walker(summary, raw_pkt, idx)
            if len(self.walker) > 300: self.walker.pop(0)

    def _add_to_walker(self, summary, raw_pkt, idx):
        proto = summary["protocol"]
        attr = f"pkt_{proto.lower()}" if f"pkt_{proto.lower()}" in [p[0] for p in THEMES[self.current_theme]] else "pkt_other"
        line = f"#{idx:<4} | {summary['src']:<22} → {summary['dst']:<22} | {proto:<6} | {summary['summary'][:80]}"
        btn = urwid.Button(line)
        btn._packet = raw_pkt
        btn._idx = idx
        urwid.connect_signal(btn, 'click', self.on_select)
        styled = urwid.AttrMap(btn, attr, focus_map='text_focus')
        self.walker.append(styled)
        self.header.set_text(f" vimShark | {self.interface} | Packets: {self.packet_count} | Theme: {self.current_theme}")

    def on_select(self, btn):
        pkt = getattr(btn, '_packet', None)
        if not pkt: return
        self.selected_index = getattr(btn, '_idx', 0)
        summary = self.dissector.dissect_to_dict(pkt)
        # Details
        details = [urwid.Text(f"### Packet #{self.selected_index} ###")]
        for layer in [Ether, IP, IPv6, ARP, TCP, UDP, DNS, ICMP, NTP, Raw]:
            if pkt.haslayer(layer):
                details.append(urwid.Text(f"── {layer.__name__} ──"))
                for field in pkt[layer].fields_desc:
                    val = getattr(pkt[layer], field.name, "N/A")
                    details.append(urwid.Text(f"  {field.name:<15}: {val}"))
        payload_text = self.dissector.parse_payloads_to_string(pkt)
        if payload_text: details.append(urwid.Text("\n" + payload_text))
        if TCP in pkt:
            stream = self.dissector.get_flow_data(pkt)
            if stream:
                details.append(urwid.Text(f"\nReassembled Stream ({len(stream)} bytes):\n"))
                details.append(urwid.Text(stream[:1200].decode('utf-8', errors='ignore')))

        self.details_walker.clear()
        self.details_walker.extend(details)
        # Hex
        hexdump = self.dissector.generate_hexdump(bytes(pkt))
        self.hex_walker.clear()
        self.hex_walker.extend([urwid.Text(line) for line in hexdump.splitlines()])

    def open_validation_modal(self):
        """Creates an interactive overlay for triggering active ARP validation probes."""
        target_edit = urwid.Edit("Target IP Address: ", "192.168.1.1")
        ok_button = urwid.Button("DISPATCH PROBE")
        cancel_button = urwid.Button("CANCEL")
        modal_content = urwid.Pile([
            urwid.Text("--- Active Security Validation ---"),
            urwid.Divider(),
            target_edit,
            urwid.Divider(),
            urwid.Columns([
                urwid.AttrMap(ok_button, 'selected', focus_map='text_focus'),
                urwid.AttrMap(cancel_button, 'selected', focus_map='text_focus')
            ], dividechars=2)
        ])
        modal_box = urwid.LineBox(urwid.Filler(modal_content, valign='middle'), title="IP-MAC Binding Verification")
        def close_modal(button): self.main_frame.body = urwid.AttrMap(self.body, 'bg')
        def start_validation(button):
            ip_to_probe = target_edit.get_edit_text()
            close_modal(None)
            threading.Thread(target=self.auditor.trigger_active_validation, args=(ip_to_probe, self.interface), daemon=True).start()
        urwid.connect_signal(cancel_button, 'click', close_modal)
        urwid.connect_signal(ok_button, 'click', start_validation)
        self.main_frame.body = urwid.Overlay(urwid.AttrMap(modal_box, 'bg'), urwid.AttrMap(self.body, 'bg'), 'center', 50, 'middle', 10)

    def clear_packets(self):
        """Resets the internal packet buffer and clears the UI components."""
        self.all_packets.clear()
        self.walker.clear()
        self.packet_count = 0
        self.details_walker.clear()
        self.details_walker.append(urwid.Text("Select a packet..."))
        self.hex_walker.clear()
        self.hex_walker.append(urwid.Text("Hex dump..."))
        self.queue_alert("Telemetry buffer and display cleared.")
        self.header.set_text(f" vimShark | {self.interface} | Packets: 0 | Theme: {self.current_theme}")

    def follow_stream(self):
        """Identifies and displays the reassembled payload for a TCP or UDP conversation."""
        focus_widget, _ = self.packet_list.get_focus()
        if not focus_widget:
            self.queue_alert("No packet selected to follow")
            return
        
        btn = focus_widget.base_widget
        pkt = getattr(btn, '_packet', None)
        
        if not pkt or not (TCP in pkt or UDP in pkt):
            self.queue_alert("Select a TCP or UDP packet to follow the stream")
            return

        proto = TCP if TCP in pkt else UDP
        ip_layer = IP if IP in pkt else (IPv6 if IPv6 in pkt else None)
        if not ip_layer: return

        s_ip, d_ip = pkt[ip_layer].src, pkt[ip_layer].dst
        s_port, d_port = pkt[proto].sport, pkt[proto].dport

        stream_widgets = [urwid.Text(("header", f" Follow {proto.__name__} Stream: {s_ip}:{s_port} <-> {d_ip}:{d_port} ")), urwid.Divider("-")]
        
        for _, p, _ in self.all_packets:
            if proto not in p or ip_layer not in p: continue
            p_ip, p_pr = p[ip_layer], p[proto]
            
            is_fwd = (p_ip.src == s_ip and p_pr.sport == s_port and p_ip.dst == d_ip and p_pr.dport == d_port)
            is_rev = (p_ip.src == d_ip and p_pr.sport == d_port and p_ip.dst == s_ip and p_pr.dport == s_port)
            
            if (is_fwd or is_rev) and Raw in p:
                payload = p[Raw].load
                text = "".join([chr(b) if 32 <= b <= 126 or b in (10, 13) else "." for b in payload])
                color = 'pkt_tcp' if is_fwd else 'pkt_udp'
                stream_widgets.append(urwid.Text((color, f"{'>>' if is_fwd else '<<'} {text}")))

        if len(stream_widgets) <= 2:
            self.queue_alert("No payload data found in this stream")
            return

        def close_stream(button): self.main_frame.body = urwid.AttrMap(self.body, 'bg')
        c_btn = urwid.Button("Close Stream View")
        urwid.connect_signal(c_btn, 'click', close_stream)
        
        listbox = urwid.ListBox(urwid.SimpleFocusListWalker(stream_widgets + [urwid.Divider("-"), urwid.AttrMap(c_btn, 'selected', 'text_focus')]))
        self.main_frame.body = urwid.Overlay(urwid.AttrMap(urwid.LineBox(listbox, title="Stream Reassembly"), 'bg'), urwid.AttrMap(self.body, 'bg'), 'center', ('relative', 85), 'middle', ('relative', 85))

    def capture_worker(self):
        def handler(pkt):
            if not self.is_running or (self.capture_paused and not self.pcap_file): return
            self.telemetry.accumulate(len(pkt))
            self.dissector.track_tcp_flow(pkt)
            
            if self.pcap_writer: self.pcap_writer.write(pkt)
                
            self.auditor.passive_arp_sniff_hook(pkt)
            summary = self.dissector.dissect_to_dict(pkt)
            try: self.pkt_queue.put_nowait((summary, pkt))
            except queue.Full: pass

        # Use a loop with a timeout to allow the thread to periodically check self.is_running
        # and exit gracefully even when no network traffic is present.
        if self.pcap_file:
            self.queue_alert(f"[*] Analyzing PCAP: {self.pcap_file}")
            sniff(offline=self.pcap_file, prn=handler, store=False, 
                  stop_filter=lambda x: not self.is_running)
            self.queue_alert("[*] PCAP analysis complete.")
        else:
            while self.is_running:
                sniff(iface=self.interface, prn=handler, store=False, 
                      stop_filter=lambda x: not self.is_running, timeout=1.0)

    def refresh(self, loop, _=None):
        # Packets
        while not self.pkt_queue.empty():
            try:
                summary, pkt = self.pkt_queue.get_nowait()
                self.add_packet(summary, pkt)
            except queue.Empty: break

        # Alerts
        while not self.alert_queue.empty():
            try:
                msg = self.alert_queue.get_nowait()
                self.alert_walker.append(urwid.Text(f" {msg}"))
                if len(self.alert_walker) > 50:
                    self.alert_walker.pop(0)
            except queue.Empty: break

        # Telemetry
        pr, br = self.telemetry.tick()
        self.rate_pkt.set_text(f"Packet Rate: {pr} p/s {self.telemetry.generate_sparkline('packets')}")
        self.rate_byte.set_text(f"Data Rate:   {br} B/s {self.telemetry.generate_sparkline('bytes')}")

        loop.set_alarm_in(0.1, self.refresh)

    def handle_input(self, key):
        if key in ('q', 'Q', 'esc'):
            if isinstance(self.main_frame.body, urwid.Overlay):
                self.main_frame.body = urwid.AttrMap(self.body, 'bg')
                return
            self.is_running = False
            raise urwid.ExitMainLoop()
        elif key in ('t', 'T'): self.update_theme()
        elif key in ('p', 'P'):
            self.capture_paused = not self.capture_paused
            status = "PAUSED" if self.capture_paused else "RESUMED"
            self.queue_alert(f"Capture {status}")
        elif key in ('c', 'C'): self.clear_packets()
        elif key in ('f', 'F'): self.follow_stream()
        elif key == '/':
            self.left_pane.focus_position = 0
            self.list_container.focus_position = 0
        elif key in ('v', 'V'): self.open_validation_modal()

    def run(self):
        if not self.pcap_file and os.getuid() != 0:
            print("[!] Run with sudo!")
            sys.exit(1)

        palette = THEMES[self.current_theme]

        screen = urwid.raw_display.Screen()
        screen.set_terminal_properties(colors=256)

        self.loop = urwid.MainLoop(
            self.root,
            palette,
            screen=screen,
            unhandled_input=self.handle_input
        )

        self.cap_thread = threading.Thread(target=self.capture_worker, daemon=True)
        self.cap_thread.start()

        self.loop.set_alarm_in(0.1, self.refresh)
        try:
            self.loop.run()
        except (KeyboardInterrupt, SystemExit):
            pass
        finally:
            self.is_running = False
            # Ensure the capture thread is joined to allow clean terminal state restoration
            self.cap_thread.join(timeout=1.5)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="vimShark: Terminal Packet Analyzer")
    parser.add_argument("-i", "--interface", default="eth0", help="Network interface to sniff on")
    parser.add_argument("-r", "--read", help="Read a PCAP file for analysis")
    parser.add_argument("-o", "--output", help="Output captured packets to a PCAP file")
    args = parser.parse_args()

    if not args.read: print(f"[+] Starting vimShark on {args.interface} (sudo required)")
    else: print(f"[+] Loading {args.read} for dissection...")
    app = vimSharkApp(interface=args.interface, pcap_file=args.read, output_file=args.output)
    app.run()