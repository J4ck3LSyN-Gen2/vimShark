#!/usr/bin/env python3
import sys, os
# Support for local package installation (mitigation for sudo/venv conflicts)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path: sys.path.insert(0, SCRIPT_DIR)
import time, threading, queue, re, socket
try: import fcntl
except ImportError: fcntl = None
import struct, argparse, logging, hashlib, ssl
from datetime import datetime
try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
    x509 = None
    hashes = None
    default_backend = None
from collections import deque
from typing import Dict, List, Optional, Any, Tuple, Callable
import urwid, dpkt

try: import dpkt.ntp  # noqa: F401
except Exception: pass
try: import dpkt.icmp6  # noqa: F401
except Exception: pass
try: import dpkt.ssl  # noqa: F401
except Exception: pass
try: import pcapy
except ImportError: 
    print("[!] pcapy-ng is required: pip install pcapy-ng");sys.exit(1)

try:
    from scapy.all import ARP as ScapyARP, Ether as ScapyEther, srp as scapy_srp
    SCAPY_AVAILABLE = True
except Exception: SCAPY_AVAILABLE = False

__version__ = "0.2.0-dev"
__author__ = "J4ck3LSyN"

# ==============================================================================
# LOGGING
# ==============================================================================

logging.basicConfig(
    filename=os.path.join(SCRIPT_DIR, "vimshark.log"),
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("vimshark")

# ==============================================================================
# THEMES
# ==============================================================================

THEMES: Dict[str, List[Tuple]] = {
    "arch_yuki": [
        ('bg', 'default', 'default', 'default', '#e0def4', '#1a1625'),
        ('header', 'black', 'light magenta', 'bold', '#1a1625', '#c4a7e7'),
        ('footer', 'light gray', 'black', None, '#908caa', '#15101f'),
        ('border', 'dark magenta', 'default', 'default', '#6e6a86', '#1a1625'),
        ('selected', 'black', 'light cyan', 'standout', '#1a1625', '#ebbcba'),
        ('pkt_tcp', 'light cyan', 'default', 'default', '#9ccfd8', '#1a1625'),
        ('pkt_udp', 'light magenta', 'default', 'default', '#c4a7e7', '#1a1625'),
        ('pkt_arp', 'yellow', 'default', 'default', '#f6c177', '#1a1625'),
        ('pkt_dns', 'light cyan', 'default', 'default', '#ebbcba', '#1a1625'),
        ('pkt_icmp', 'light red', 'default', 'default', '#eb6f92', '#1a1625'),
        ('pkt_icmp6', 'light red', 'default', 'default', '#eb6f92', '#1a1625'),
        ('pkt_http', 'light green', 'default', 'default', '#31748f', '#1a1625'),
        ('pkt_tls', 'light blue', 'default', 'default', '#c4a7e7', '#1a1625'),
        ('pkt_ntp', 'yellow', 'default', 'default', '#f6c177', '#1a1625'),
        ('pkt_other', 'light gray', 'default', 'default', '#908caa', '#1a1625'),
        ('spark_bar', 'light magenta', 'default', None, '#c4a7e7', '#1a1625'),
        ('text_focus', 'black', 'light magenta', None, '#1a1625', '#c4a7e7'),
    ],
    "neon_sakura": [
        ('bg', 'default', 'default', 'default', '#ffe6f2', '#0d0a1f'),
        ('header', 'white', 'dark magenta', 'bold', '#ffffff', '#d672ff'),
        ('footer', 'light gray', 'black', None, '#a78bcf', '#100c24'),
        ('border', 'light magenta', 'default', 'default', '#6e4b9e', '#0d0a1f'),
        ('selected', 'black', 'light green', 'standout', '#0d0a1f', '#7effc0'),
        ('pkt_tcp', 'light cyan', 'default', 'default', '#7ee8fa', '#0d0a1f'),
        ('pkt_udp', 'light magenta', 'default', 'default', '#ff6ec7', '#0d0a1f'),
        ('pkt_arp', 'yellow', 'default', 'default', '#ffe066', '#0d0a1f'),
        ('pkt_dns', 'light cyan', 'default', 'default', '#9af7e0', '#0d0a1f'),
        ('pkt_icmp', 'light red', 'default', 'default', '#ff5f9e', '#0d0a1f'),
        ('pkt_icmp6', 'light red', 'default', 'default', '#ff4f8b', '#0d0a1f'),
        ('pkt_http', 'light green', 'default', 'default', '#9dffb0', '#0d0a1f'),
        ('pkt_tls', 'light blue', 'default', 'default', '#b6a3ff', '#0d0a1f'),
        ('pkt_ntp', 'yellow', 'default', 'default', '#ffd6a5', '#0d0a1f'),
        ('pkt_other', 'light gray', 'default', 'default', '#8e7fb5', '#0d0a1f'),
        ('spark_bar', 'light cyan', 'default', None, '#7ee8fa', '#0d0a1f'),
        ('text_focus', 'black', 'light cyan', None, '#0d0a1f', '#7ee8fa'),
    ],
    "vapor_noir": [
        ('bg', 'default', 'default', 'default', '#e8e0ff', '#120e1e'),
        ('header', 'black', 'light blue', 'bold', '#120e1e', '#8ad7ff'),
        ('footer', 'dark gray', 'black', None, '#7a6f99', '#0e0a18'),
        ('border', 'dark blue', 'default', 'default', '#4b3f73', '#120e1e'),
        ('selected', 'black', 'light magenta', 'standout', '#120e1e', '#ff8de0'),
        ('pkt_tcp', 'light blue', 'default', 'default', '#8ad7ff', '#120e1e'),
        ('pkt_udp', 'light magenta', 'default', 'default', '#ff8de0', '#120e1e'),
        ('pkt_arp', 'yellow', 'default', 'default', '#ffe9a8', '#120e1e'),
        ('pkt_dns', 'light cyan', 'default', 'default', '#aef0ff', '#120e1e'),
        ('pkt_icmp', 'light red', 'default', 'default', '#ff7a93', '#120e1e'),
        ('pkt_icmp6', 'light red', 'default', 'default', '#ff6688', '#120e1e'),
        ('pkt_http', 'light green', 'default', 'default', '#b3ffd9', '#120e1e'),
        ('pkt_tls', 'light blue', 'default', 'default', '#bcaaff', '#120e1e'),
        ('pkt_ntp', 'yellow', 'default', 'default', '#ffd6f0', '#120e1e'),
        ('pkt_other', 'light gray', 'default', 'default', '#8c80ad', '#120e1e'),
        ('spark_bar', 'light magenta', 'default', None, '#ff8de0', '#120e1e'),
        ('text_focus', 'black', 'light blue', None, '#120e1e', '#8ad7ff'),
    ],
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
        ('pkt_icmp6', 'light red', 'default', 'default', '#ff8787', '#0f1419'),
        ('pkt_http', 'dark green', 'default', 'default', '#00af5f', '#0f1419'),
        ('pkt_tls', 'light blue', 'default', 'default', '#5fafff', '#0f1419'),
        ('pkt_ntp', 'yellow', 'default', 'default', '#ffaf00', '#0f1419'),
        ('pkt_other', 'light gray', 'default', 'default', '#8a95a5', '#0f1419'),
        ('spark_bar', 'light green', 'default', None, '#00ff87', '#0f1419'),
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
        ('pkt_icmp6', 'light red', 'default', 'default', '#fb4934', '#282828'),
        ('pkt_http', 'dark green', 'default', 'default', '#b8bb26', '#282828'),
        ('pkt_tls', 'light blue', 'default', 'default', '#83a598', '#282828'),
        ('pkt_ntp', 'yellow', 'default', 'default', '#fabd2f', '#282828'),
        ('pkt_other', 'light gray', 'default', 'default', '#a89984', '#282828'),
        ('spark_bar', 'light green', 'default', None, '#b8bb26', '#282828'),
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
        ('pkt_icmp6', 'light red', 'default', 'default', '#ff5555', '#282a36'),
        ('pkt_http', 'dark green', 'default', 'default', '#50fa7b', '#282a36'),
        ('pkt_tls', 'light blue', 'default', 'default', '#8be9fd', '#282a36'),
        ('pkt_ntp', 'yellow', 'default', 'default', '#f1fa8c', '#282a36'),
        ('pkt_other', 'light gray', 'default', 'default', '#f8f8f2', '#282a36'),
        ('spark_bar', 'light green', 'default', None, '#50fa7b', '#282a36'),
        ('text_focus', 'white', 'dark magenta', None, '#ffffff', '#bd93f9'),
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
        ('pkt_icmp6', 'light red', 'default', 'default', '#ff0055', '#000b1e'),
        ('pkt_http', 'dark green', 'default', 'default', '#00ff00', '#000b1e'),
        ('pkt_tls', 'light blue', 'default', 'default', '#00afff', '#000b1e'),
        ('pkt_ntp', 'yellow', 'default', 'default', '#ffff00', '#000b1e'),
        ('pkt_other', 'white', 'default', 'default', '#00ff00', '#000b1e'),
        ('spark_bar', 'light green', 'default', None, '#00ff00', '#000b1e'),
        ('text_focus', 'black', 'light cyan', None, '#000000', '#00ffff'),
    ],
}

# ==============================================================================
# UTILITIES & TELEMETRY
# ==============================================================================

def mac_to_str(address: bytes) -> str: 
    return ':'.join('%02x' % b for b in address)


def ip_to_str(address: bytes) -> str: 
    return socket.inet_ntop(socket.AF_INET, address)


def ip6_to_str(address: bytes) -> str: 
    return socket.inet_ntop(socket.AF_INET6, address)


# ioctl request codes (Linux)
_SIOCGIFHWADDR = 0x8927
_SIOCGIFADDR = 0x8915


def get_iface_mac(iface: str) -> bytes:
    """Return the raw 6-byte MAC address for an interface via ioctl."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if sys.platform != 'linux' or fcntl is None:
        return b'\x00' * 6
    try:
        info = fcntl.ioctl(s.fileno(), _SIOCGIFHWADDR, struct.pack('256s', iface[:15].encode()))
        return info[18:24]
    finally:
        s.close()
    return b'\x00' * 6


def get_iface_ip(iface: str) -> bytes:
    """Return the raw 4-byte IPv4 address for an interface via ioctl."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        if sys.platform != 'linux' or fcntl is None:
            return b'\x00' * 4
        info = fcntl.ioctl(s.fileno(), _SIOCGIFADDR, struct.pack('256s', iface[:15].encode()))
        return info[20:24]
    finally:
        s.close()
    return b'\x00' * 4


def load_arp_cache() -> Dict[str, str]:
    """Pre-seed the ARP table from the kernel's neighbor cache (/proc/net/arp)."""
    table: Dict[str, str] = {}
    try:
        with open('/proc/net/arp') as f:
            next(f, None)  # header line
            for line in f:
                parts = line.split()
                if len(parts) >= 4:
                    ip_addr, mac = parts[0], parts[3]
                    if mac and mac != '00:00:00:00:00:00':
                        table[ip_addr] = mac
    except Exception as e:
        logger.debug("ARP cache preload failed: %s", e)
    return table


class TrafficTelemetry:
    def __init__(self, max_history: int = 40):
        self.packet_history: deque = deque([0] * max_history, maxlen=max_history)
        self.byte_history: deque = deque([0] * max_history, maxlen=max_history)
        self.p_acc = 0
        self.b_acc = 0
        self.last_tick = time.time()
        self.blocks = ' ▂▃▄▅▆▇█'
        self.p_rate = 0.0
        self.b_rate = 0.0

    def accumulate(self, length: int) -> None:
        self.p_acc += 1
        self.b_acc += length

    def tick(self) -> Tuple[float, float]:
        """Update rates with smoothing. Returns (packets/s, bytes/s)."""
        now = time.time()
        elapsed = now - self.last_tick
        if elapsed >= 0.1:
            p_inst = self.p_acc / elapsed
            b_inst = self.b_acc / elapsed
            alpha = 0.6
            self.p_rate = (alpha * p_inst) + ((1.0 - alpha) * self.p_rate) if self.p_rate > 0 else p_inst
            self.b_rate = (alpha * b_inst) + ((1.0 - alpha) * self.b_rate) if self.b_rate > 0 else b_inst
            self.packet_history.append(int(p_inst))
            self.byte_history.append(int(b_inst))
            self.p_acc = 0
            self.b_acc = 0
            self.last_tick = now
        return self.p_rate, self.b_rate

    @staticmethod
    def format_unit(val: float, is_bytes: bool = False) -> str:
        if not is_bytes:
            if val >= 1000000: return f"{val/1000000:.1f}M"
            if val >= 1000: return f"{val/1000:.1f}K"
            return str(int(val))
        for unit in ['', 'K', 'M', 'G', 'T']:
            if val < 1024: return f"{val:.1f}{unit}B" if unit else f"{int(val)}B"
            val /= 1024
        return f"{val:.1f}PB"

    def get_sparkline(self, metric: str = "p") -> str:
        h = list(self.packet_history if metric == "p" else self.byte_history)
        m_max = max(h) if h and max(h) > 0 else 1
        return "".join(self.blocks[min(7, int(v * 7 / m_max))] for v in h)


# ==============================================================================
# PACKET STORE
# ==============================================================================

class PacketStore:
    """Owns all captured packet bytes/summaries. Capture thread writes via
    add(); UI thread reads via get()/all_indices(). Widgets only ever carry
    an integer index - never raw bytes or dpkt objects - eliminating the
    cross-thread / dangling-reference patterns that caused the segfault."""

    def __init__(self, max_packets: int = 5000):
        self._lock = threading.Lock()
        self._packets: Dict[int, Tuple[bytes, Dict[str, Any], float]] = {}
        self._order: deque = deque()
        self._next_idx = 0
        self.max_packets = max_packets

    def add(self, raw: bytes, summary: Dict[str, Any], ts: float = 0.0) -> int:
        with self._lock:
            idx = self._next_idx
            self._next_idx += 1
            self._packets[idx] = (raw, summary, ts)
            self._order.append(idx)
            while len(self._order) > self.max_packets:
                old = self._order.popleft()
                self._packets.pop(old, None)
            return idx

    def get(self, idx: int) -> Optional[Tuple[bytes, Dict[str, Any], float]]:
        with self._lock:
            return self._packets.get(idx)

    def all_indices(self) -> List[int]:
        with self._lock:
            return list(self._order)

    def clear(self) -> None:
        with self._lock:
            self._packets.clear()
            self._order.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._order)

# ==============================================================================
# UPGRADED DISSECTION ENGINE (v0.4 - Enhanced TLS + JA3)
# ==============================================================================

class FastDissector:
    """High-performance, multi-protocol packet dissector with robust TLS
    parsing, JA3 fingerprinting, enhanced certificate details, and credential detection."""

    _CRED_PATTERNS: List[Tuple[re.Pattern, str]] = [
        (re.compile(rb'(?i)authorization:\s*basic\s+\S+'), 'HTTP Basic Auth'),
        (re.compile(rb'(?i)authorization:\s*bearer\s+\S+'), 'Bearer token'),
        (re.compile(rb'(?i)\b(pass(word)?|pwd|passwd|secret|token)\s*[:=]\s*[^&\s]+'), 'Cleartext credential'),
        (re.compile(rb'(?i)cookie:[^\r\n]*sess[^\r\n]*=\S+'), 'Session cookie'),
        (re.compile(rb'(?i)^USER\s+\S+', re.MULTILINE), 'FTP/IMAP/SMTP USER'),
        (re.compile(rb'(?i)^PASS\s+\S+', re.MULTILINE), 'FTP/IMAP/SMTP PASS'),
        (re.compile(rb'(?i)api[-_]?key[:=]\s*\S+'), 'API Key'),
    ]

    @staticmethod
    def _scan_credentials(data: bytes) -> List[str]:
        if not data or len(data) > 8192:
            return []
        findings: List[str] = []
        for pattern, label in FastDissector._CRED_PATTERNS:
            try:
                if pattern.search(data):
                    findings.append(label)
            except Exception:
                continue
        return findings

    @staticmethod
    def _tcp_flag_string(flags: int) -> str:
        flag_map = [
            (dpkt.tcp.TH_FIN, 'F'), (dpkt.tcp.TH_SYN, 'S'), (dpkt.tcp.TH_RST, 'R'),
            (dpkt.tcp.TH_PUSH, 'P'), (dpkt.tcp.TH_ACK, 'A'), (dpkt.tcp.TH_URG, 'U'),
            (dpkt.tcp.TH_ECE, 'E'), (dpkt.tcp.TH_CWR, 'C'),
        ]
        return ''.join(c for bit, c in flag_map if flags & bit)

    @staticmethod
    def _safe_str(val: Any, max_len: int = 120) -> str:
        """Convert any field value to a clean, readable string."""
        if val is None:
            return "None"
        if hasattr(val, '__class__') and val.__class__.__module__.startswith('dpkt') and not isinstance(val, (bytes, bytearray)):
            return f"<{val.__class__.__name__} object>"

        if isinstance(val, (bytes, bytearray)):
            if len(val) == 6:   # MAC
                return mac_to_str(val)
            if len(val) == 4:   # IPv4
                try:
                    return socket.inet_ntop(socket.AF_INET, val)
                except Exception:
                    pass
            if len(val) == 16:  # IPv6
                try:
                    return socket.inet_ntop(socket.AF_INET6, val)
                except Exception:
                    pass

            # Try UTF-8 for text payloads
            if 0 < len(val) <= 512:
                try:
                    decoded = val.decode('utf-8', errors="replace")
                    if all(32 <= ord(c) <= 126 or c in '\n\r\t\x0b\x0c' for c in decoded):
                        res = decoded.strip()
                        return res[:max_len] + "..." if len(res) > max_len else res
                except Exception:
                    pass

            if len(val) > 48:
                return val[:48].hex() + f" ... ({len(val)} bytes)"
            return val.hex() if val else "(empty)"

        if isinstance(val, int):
            return str(val)
        if isinstance(val, list):
            if not val:
                return "[]"
            items = [FastDissector._safe_str(item, 60) for item in val[:6]]
            extra = f" ... ({len(val)} total)" if len(val) > 6 else ""
            return "[" + ", ".join(items) + extra + "]"
        if isinstance(val, dict):
            if not val:
                return "{}"
            preview = [f"{k}:{FastDissector._safe_str(v, 40)}" for k, v in list(val.items())[:4]]
            extra = " ..." if len(val) > 4 else ""
            return "{" + ", ".join(preview) + extra + "}"

        try:
            sval = str(val)
            return sval[:max_len] + "..." if len(sval) > max_len else sval
        except Exception:
            return f"<unprintable {type(val).__name__}>"

    # ====================== TLS FINGERPRINTING ======================

    @staticmethod
    def _parse_ja3_client_hello(handshake) -> Dict[str, Any]:
        """Extract data for JA3 fingerprint (ClientHello)."""
        ja3_info = {"ja3": "N/A", "ciphers": [], "extensions": [], "curves": [], "points": [], "sni": None}
        # GREASE values (RFC 8701) should be ignored for JA3 calculation
        grease = {0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
                  0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa}

        try:
            # Access the underlying codes from dpkt ciphersuite objects
            ciphers = getattr(handshake, 'ciphersuites', getattr(handshake, 'cipher_suites', []))
            ja3_info["ciphers"] = [getattr(c, 'code', c) for c in ciphers if getattr(c, 'code', c) not in grease]

            extensions = getattr(handshake, 'extensions', [])
            for ext in extensions:
                ext_type = getattr(ext, 'type', None)
                if ext_type is None or ext_type in grease:
                    continue

                ja3_info["extensions"].append(ext_type)

                # SNI
                if ext_type == 0:  # server_name
                    try:
                        for name in getattr(ext, 'server_names', []):
                            if hasattr(name, 'name'):
                                ja3_info["sni"] = name.name.decode('utf-8', errors='replace')
                    except Exception:
                        pass

                # Supported Groups (elliptic curves)
                elif ext_type == 10:
                    try:
                        data = getattr(ext, 'data', b'')
                        if len(data) >= 2:
                            list_len = struct.unpack('!H', data[:2])[0]
                            for i in range(2, 2 + list_len, 2):
                                val = struct.unpack('!H', data[i:i+2])[0]
                                if val not in grease:
                                    ja3_info["curves"].append(val)
                    except Exception:
                        pass

                # EC Point Formats
                elif ext_type == 11:
                    try:
                        data = getattr(ext, 'data', b'')
                        if len(data) >= 1:
                            list_len = data[0]
                            for i in range(1, 1 + list_len):
                                ja3_info["points"].append(data[i])
                    except Exception:
                        pass

            # Build JA3 string: SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
            ja3_str = f"{handshake.version}," \
                      f"{'-'.join(map(str, ja3_info['ciphers']))}," \
                      f"{'-'.join(map(str, ja3_info['extensions']))}," \
                      f"{'-'.join(map(str, ja3_info['curves']))}," \
                      f"{'-'.join(map(str, ja3_info['points']))}"
            ja3_info["ja3"] = hashlib.md5(ja3_str.encode('utf-8')).hexdigest()

        except Exception as e:
            logger.debug("JA3 parsing error: %s", e)

        return ja3_info

    @staticmethod
    def _parse_tls_cert(cert_der: bytes) -> Dict[str, Any]:
        """Enhanced X.509 certificate parsing."""
        info: Dict[str, Any] = {
            "subject": "Unknown", "issuer": "Unknown",
            "not_before": None, "not_after": None,
            "serial": None,
            "fingerprint_sha256": None,
            "fingerprint_sha1": None,
            "san": [],
            "crl_distribution_points": [],
            "ocsp_responders": [],
            "pubkey_algorithm": None,
            "is_expired": False,
            "is_self_signed": False,
        }

        try:
            if CRYPTOGRAPHY_AVAILABLE:
                cert = x509.load_der_x509_certificate(cert_der, default_backend())

                info["subject"] = cert.subject.rfc4514_string()
                info["issuer"] = cert.issuer.rfc4514_string()
                info["not_before"] = cert.not_valid_before_utc.isoformat()
                info["not_after"] = cert.not_valid_after_utc.isoformat()
                info["serial"] = hex(cert.serial_number)
                info["fingerprint_sha256"] = cert.fingerprint(hashes.SHA256()).hex()
                info["fingerprint_sha1"] = cert.fingerprint(hashes.SHA1()).hex()

                # Subject Alternative Names
                try:
                    san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                    info["san"] = [name.value for name in san_ext.value]
                except x509.ExtensionNotFound:
                    pass

                # Public Key Info
                info["pubkey_algorithm"] = cert.public_key().__class__.__name__

                # CRL and OCSP
                for ext in cert.extensions:
                    if isinstance(ext.value, x509.CRLDistributionPoints):
                        for dp in ext.value:
                            for point in dp.full_name:
                                if isinstance(point, x509.UniformResourceIdentifier):
                                    info["crl_distribution_points"].append(point.value)
                    if isinstance(ext.value, x509.AuthorityInformationAccess):
                        for ad in ext.value:
                            if ad.access_method == x509.oid.AuthorityInformationAccessOID.OCSP:
                                if isinstance(ad.access_location, x509.UniformResourceIdentifier):
                                    info["ocsp_responders"].append(ad.access_location.value)

                # Basic checks
                now = datetime.utcnow()
                info["is_expired"] = cert.not_valid_after_utc < now
                info["is_self_signed"] = cert.subject == cert.issuer

            else:
                info["fingerprint_sha256"] = hashlib.sha256(cert_der).hex()
                info["subject"] = "Install cryptography for full parsing"

        except Exception as e:
            logger.debug("Cert parse error: %s", e)
            if not info["fingerprint_sha256"]:
                info["fingerprint_sha256"] = hashlib.sha256(cert_der).hex()

        return info

    @staticmethod
    def _parse_tls_handshake(tcp_payload: bytes) -> Dict[str, Any]:
        """Robust TLS handshake parser with JA3 support."""
        result: Dict[str, Any] = {
            "certs": [],
            "sni": None,
            "version": None,
            "cipher": None,
            "ja3": None,
            "ja3_info": {},
            "ocsp_stapled": False,
            "handshake_type": "Unknown",
            "tls13": False,
        }

        if not tcp_payload or len(tcp_payload) < 5:
            return result

        try:
            tls = dpkt.ssl.TLS(tcp_payload)
            records = getattr(tls, 'records', [tls])

            for record in records:
                if getattr(record, 'type', None) != 22:  # Handshake
                    continue
                try:
                    handshake = dpkt.ssl.TLSHandshake(record.data)
                    hs_type = getattr(handshake, 'type', None)

                    if hs_type == 1:  # ClientHello
                        result["handshake_type"] = "ClientHello"
                        inner = handshake.data
                        result["version"] = f"0x{inner.version:04x}"
                        ja3_data = FastDissector._parse_ja3_client_hello(inner)
                        result["ja3"] = ja3_data["ja3"]
                        result["ja3_info"] = ja3_data
                        result["sni"] = ja3_data["sni"]

                    elif hs_type == 2:  # ServerHello
                        result["handshake_type"] = "ServerHello"
                        inner = handshake.data
                        if hasattr(inner, 'version'):
                            result["version"] = f"0x{inner.version:04x}"
                            if inner.version == 0x0304:
                                result["tls13"] = True
                        cipher = getattr(inner, 'ciphersuite', getattr(inner, 'cipher_suite', None))
                        if cipher:
                            result["cipher"] = f"0x{getattr(cipher, 'code', cipher):04x}"

                    elif hs_type == 11:  # Certificate
                        result["handshake_type"] = "Certificate"
                        inner = handshake.data
                        for cert_der in getattr(inner, 'certificates', []):
                            if isinstance(cert_der, (bytes, bytearray)) and len(cert_der) > 0:
                                parsed = FastDissector._parse_tls_cert(cert_der)
                                result["certs"].append(parsed)

                    elif hs_type == 22:  # Certificate Status (OCSP Stapling)
                        result["ocsp_stapled"] = True

                except Exception as inner_e:
                    logger.debug("Inner handshake parse failed: %s", inner_e)

        except Exception as e:
            logger.debug("TLS handshake parse error: %s", e)

        return result

    @staticmethod
    def _dissect_layer(layer: Any, depth: int = 0) -> List[Tuple[str, Dict[str, Any]]]:
        """Recursively dissect nested protocol layers."""
        layers: List[Tuple[str, Dict[str, Any]]] = []
        if layer is None or isinstance(layer, (bytes, bytearray)) or depth > 12:
            return layers

        try:
            raw_name = layer.__class__.__name__
            layer_name = "IPv4" if raw_name == "IP" else ("IPv6" if raw_name == "IP6" else raw_name)
            fields: Dict[str, Any] = {}

            if hasattr(layer, '__hdr__'):
                for hdr_item in getattr(layer, '__hdr__', []):
                    name = hdr_item[0]
                    fields[name] = getattr(layer, name)
            else:
                for attr in dir(layer):
                    if attr.startswith('_') or attr in ('data', 'unpack', 'pack', 'off', 'sum', '__'):
                        continue
                    val = getattr(layer, attr, None)
                    if not callable(val):
                        fields[attr] = val

            layers.append((layer_name, fields))

            payload = getattr(layer, 'data', None)
            if payload and hasattr(payload, '__class__') and payload.__class__.__module__.startswith('dpkt'):
                layers.extend(FastDissector._dissect_layer(payload, depth + 1))

        except Exception as e:
            logger.debug("layer dissection error: %s", e)

        return layers

    @staticmethod
    def dissect(raw_pkt: bytes) -> Dict[str, Any]:
        """Main dissection entry point."""
        res: Dict[str, Any] = {
            "proto": "OTHER", "src": "N/A", "dst": "N/A", "summary": "Unknown Frame",
            "len": len(raw_pkt), "layers": [], "creds": [], "ports": [], "tls_info": {},
        }

        try:
            eth = dpkt.ethernet.Ethernet(raw_pkt)
            res["layers"] = FastDissector._dissect_layer(eth)

            payload = eth.data

            if isinstance(payload, dpkt.arp.ARP):
                arp = payload
                res["proto"] = "ARP"
                res["src"] = ip_to_str(arp.spa)
                res["dst"] = ip_to_str(arp.tpa)
                op = "Request" if arp.op == dpkt.arp.ARP_OP_REQUEST else "Reply"
                res["summary"] = f"ARP {op} {res['src']} -> {res['dst']}"

            elif isinstance(payload, (dpkt.ip.IP, dpkt.ip6.IP6)):
                ip_pkt = payload
                is_v6 = isinstance(ip_pkt, dpkt.ip6.IP6)

                res["src"] = (ip6_to_str if is_v6 else ip_to_str)(ip_pkt.src)
                res["dst"] = (ip6_to_str if is_v6 else ip_to_str)(ip_pkt.dst)
                res["proto"] = "IPv6" if is_v6 else "IPv4"

                if isinstance(ip_pkt.data, dpkt.tcp.TCP):
                    tcp = ip_pkt.data
                    res["proto"] = "TCP"
                    res["src"] += f":{tcp.sport}"
                    res["dst"] += f":{tcp.dport}"
                    res["ports"] = [tcp.sport, tcp.dport]
                    flagstr = FastDissector._tcp_flag_string(tcp.flags)
                    res["summary"] = f"TCP {tcp.sport}->{tcp.dport} [{flagstr}] Seq={tcp.seq} Ack={tcp.ack} Len={len(tcp.data or b'')}"

                    if tcp.data:
                        res["creds"] = FastDissector._scan_credentials(tcp.data)

                    # HTTP
                    if tcp.dport in (80, 8080) or tcp.sport in (80, 8080):
                        try:
                            data = tcp.data
                            http = (dpkt.http.Response if data.startswith(b'HTTP/') else dpkt.http.Request)(data)
                            res["proto"] = "HTTP"
                            res["summary"] = f"HTTP {getattr(http, 'method', http.version)} {getattr(http, 'uri', getattr(http, 'status', ''))}"
                            tcp.data = http
                        except Exception:
                            pass

                    # TLS
                    elif tcp.dport == 443 or tcp.sport == 443:
                        res["proto"] = "TLS"
                        tls_info = FastDissector._parse_tls_handshake(tcp.data or b'')
                        res["tls_info"] = tls_info

                        sni_part = f" SNI:{tls_info['sni']}" if tls_info.get('sni') else ""
                        ja3_part = f" JA3:{tls_info['ja3'][:12]}" if tls_info.get('ja3') and tls_info['ja3'] != "N/A" else ""
                        res["summary"] = f"TLS {tcp.sport}->{tcp.dport} v{tls_info.get('version','?')}{ja3_part} Certs:{len(tls_info['certs'])}{sni_part}"

                elif isinstance(ip_pkt.data, dpkt.udp.UDP):
                    udp = ip_pkt.data
                    res["proto"] = "UDP"
                    res["src"] += f":{udp.sport}"
                    res["dst"] += f":{udp.dport}"
                    res["ports"] = [udp.sport, udp.dport]
                    res["summary"] = f"UDP {udp.sport}->{udp.dport} Len={udp.ulen}"

                    if udp.dport == 53 or udp.sport == 53:
                        try:
                            dns = dpkt.dns.DNS(udp.data)
                            res["proto"] = "DNS"
                            qr = 'Query' if dns.qr == 0 else 'Response'
                            qname = dns.qd[0].name.decode('utf-8', errors='replace') if dns.qd else ""
                            res["summary"] = f"DNS {qr} {qname}"
                        except Exception:
                            pass
                    elif udp.dport == 123 or udp.sport == 123:
                        try:
                            ntp = dpkt.ntp.NTP(udp.data)
                            res["proto"] = "NTP"
                            res["summary"] = f"NTP v{ntp.v} Mode {ntp.mode} Stratum {ntp.stratum}"
                        except Exception:
                            pass

                # ICMP / ICMPv6 (unchanged)
                elif isinstance(ip_pkt.data, dpkt.icmp.ICMP):
                    icmp = ip_pkt.data
                    res["proto"] = "ICMP"
                    res["summary"] = f"ICMP Type={icmp.type} Code={icmp.code}"

                elif hasattr(dpkt, 'icmp6') and isinstance(ip_pkt.data, dpkt.icmp6.ICMP6):
                    icmp6 = ip_pkt.data
                    res["proto"] = "ICMPv6"
                    res["summary"] = f"ICMPv6 Type={icmp6.type} Code={icmp6.code}"

            # VLAN fallback
            elif eth.type == 0x8100:
                res["proto"] = "VLAN"
                res["summary"] = "802.1Q VLAN Frame"

            # Re-dissect after enrichment
            res["layers"] = FastDissector._dissect_layer(eth)

        except Exception as e:
            logger.debug("dissect error: %s", e)

        return res

    @staticmethod
    def get_hexdump(data: bytes, max_bytes: int = 1024) -> str:
        """Generate nice hexdump."""
        truncated = len(data) > max_bytes
        view = data[:max_bytes]
        lines = []
        for i in range(0, len(view), 16):
            chunk = view[i:i + 16]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            lines.append(f"{i:04x}  {hex_part:<47}  {ascii_part}")
        if truncated:
            lines.append(f"... truncated ({len(data)} bytes total) ...")
        return "\n".join(lines)
        
# ==============================================================================
# IP REASSEMBLER
# ==============================================================================

class IPReassembler:
    """Stateful IPv4 fragmentation reassembler."""
    def __init__(self, max_age: float = 30.0):
        self.fragments: Dict[Tuple, Dict[int, bytes]] = {}
        self.finished: Dict[Tuple, int] = {}
        self.timestamps: Dict[Tuple, float] = {}
        self.max_age = max_age

    def process(self, ip: dpkt.ip.IP) -> Optional[bytes]:
        now = time.time()
        # Clean up expired buffers
        expired = [k for k, ts in self.timestamps.items() if now - ts > self.max_age]
        for k in expired: self._clear(k)

        # Fragment offset is in 8-byte units
        offset = (ip.off & dpkt.ip.IP_OFFMASK) * 8
        mf = bool(ip.off & dpkt.ip.IP_MF)
        
        key = (ip.src, ip.dst, ip.p, ip.id)
        self.timestamps[key] = now
        
        if key not in self.fragments:
            self.fragments[key] = {}
        
        self.fragments[key][offset] = ip.data
        if not mf:
            self.finished[key] = offset + len(ip.data)
        
        if key in self.finished:
            total, curr, parts = self.finished[key], 0, []
            while curr < total:
                if curr in self.fragments[key]:
                    chunk = self.fragments[key][curr]
                    parts.append(chunk)
                    curr += len(chunk)
                else: return None # Still missing pieces
            self._clear(key)
            return b"".join(parts)
        return None

    def _clear(self, key):
        self.fragments.pop(key, None); self.finished.pop(key, None); self.timestamps.pop(key, None)

# ==============================================================================
# FILTER EXPRESSIONS
# ==============================================================================

_COND_RE = re.compile(r'^\s*(\w+)\s*(==|!=)\s*(\S+)\s*$')


def _get_field(summary: Dict[str, Any], field: str):
    field = field.lower()
    if field == 'proto':
        return summary.get('proto', '')
    if field in ('src', 'srcip'):
        return summary.get('src', '').rsplit(':', 1)[0]
    if field in ('dst', 'dstip'):
        return summary.get('dst', '').rsplit(':', 1)[0]
    if field == 'sport':
        parts = summary.get('src', '').rsplit(':', 1)
        return parts[1] if len(parts) > 1 else None
    if field == 'dport':
        parts = summary.get('dst', '').rsplit(':', 1)
        return parts[1] if len(parts) > 1 else None
    if field == 'port':
        ports = []
        for key in ('src', 'dst'):
            parts = summary.get(key, '').rsplit(':', 1)
            if len(parts) > 1:
                ports.append(parts[1])
        return ports
    if field == 'len':
        return str(summary.get('len', ''))
    return None


def _compile_expr_filter(expr: str) -> Callable[[Dict[str, Any]], bool]:
    or_groups = [g.strip() for g in expr.split('||')]
    compiled_or: List[List[Tuple[Optional[str], Optional[str], str]]] = []
    for group in or_groups:
        and_parts = [p.strip() for p in group.split('&&') if p.strip()]
        conds: List[Tuple[Optional[str], Optional[str], str]] = []
        for part in and_parts:
            m = _COND_RE.match(part)
            if m:
                field, op, val = m.groups()
                conds.append((field, op, val))
            else:
                conds.append((None, None, part.lower()))
        compiled_or.append(conds)

    def matcher(summary: Dict[str, Any]) -> bool:
        for conds in compiled_or:
            ok = True
            for field, op, val in conds:
                if field is None:
                    text = f"{summary.get('summary', '')} {summary.get('proto', '')} " \
                           f"{summary.get('src', '')} {summary.get('dst', '')}".lower()
                    cond = val in text
                else:
                    actual = _get_field(summary, field)
                    if actual is None:
                        cond = False
                    elif isinstance(actual, list):
                        cond = any(str(a).lower() == val.lower() for a in actual)
                    else:
                        cond = str(actual).lower() == val.lower()
                    if op == '!=':
                        cond = not cond
                if not cond:
                    ok = False
                    break
            if ok:
                return True
        return False

    return matcher


def compile_filter(expr: str) -> Callable[[Dict[str, Any]], bool]:
    """Compile a filter string. Falls back to plain substring search on any
    parse issue, so the filter bar can never raise."""
    expr = (expr or "").strip()
    if not expr:
        return lambda summary: True
    try:
        return _compile_expr_filter(expr)
    except Exception as e:
        logger.debug("filter compile fallback: %s", e)
        val = expr.lower()

        def fallback(summary: Dict[str, Any]) -> bool:
            text = f"{summary.get('summary', '')} {summary.get('proto', '')}".lower()
            return val in text

        return fallback


# ==============================================================================
# THREAT AUDITOR
# ==============================================================================

class ThreatAuditor:
    def __init__(self, alert_cb: Callable[[str], None]):
        self.alert_cb = alert_cb
        self.arp_table: Dict[str, str] = load_arp_cache()
        self.history: set = set()

    def audit_packet(self, raw_pkt: bytes) -> None:
        try:
            eth = dpkt.ethernet.Ethernet(raw_pkt)
            if isinstance(eth.data, dpkt.arp.ARP):
                arp = eth.data
                if arp.op == dpkt.arp.ARP_OP_REPLY:
                    ip_addr = ip_to_str(arp.spa)
                    mac = mac_to_str(arp.sha)
                    known = self.arp_table.get(ip_addr)
                    if known and known != mac:
                        msg = f"ARP SPOOF: {ip_addr} moved {known} -> {mac}"
                        if msg not in self.history:
                            self.history.add(msg)
                            self.alert_cb(msg)
                    self.arp_table[ip_addr] = mac
        except Exception as e:
            logger.debug("audit_packet error: %s", e)

    def active_probe(self, target_ip: str, interface: str) -> None:
        """Send a raw ARP request to verify a host's current MAC binding."""
        try:
            sha = get_iface_mac(interface)
            spa = get_iface_ip(interface)
            tpa = socket.inet_aton(target_ip)

            arp = dpkt.arp.ARP(op=dpkt.arp.ARP_OP_REQUEST, sha=sha, spa=spa,
                                tha=b'\x00' * 6, tpa=tpa)
            eth = dpkt.ethernet.Ethernet(dst=b'\xff' * 6, src=sha,
                                          type=dpkt.ethernet.ETH_TYPE_ARP, data=arp)

            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            try:
                s.bind((interface, 0))
                s.send(bytes(eth))
            finally:
                s.close()
            self.alert_cb(f"[*] ARP probe sent to {target_ip}")
        except PermissionError:
            self.alert_cb("[!] Probe failed: requires root privileges")
        except Exception as e:
            logger.warning("raw probe failed: %s", e)
            if SCAPY_AVAILABLE:
                try:
                    pkt = ScapyEther(dst="ff:ff:ff:ff:ff:ff") / ScapyARP(pdst=target_ip)
                    scapy_srp(pkt, timeout=1, iface=interface, verbose=False)
                    self.alert_cb(f"[*] ARP probe (scapy fallback) sent to {target_ip}")
                except Exception as e2:
                    self.alert_cb(f"[!] Probe failed: {e2}")
            else:
                self.alert_cb(f"[!] Probe failed: {e} (install scapy for a fallback)")


# ==============================================================================
# CORE APPLICATION
# ==============================================================================

class vimSharkApp:
    def __init__(self, interface: str = "eth0", read_pcap: Optional[str] = None,
                 write_pcap: Optional[str] = None, max_packets: int = 5000,
                 batch_size: int = 100, max_rate: float = 0.0,
                 max_display: int = 500):
        self.interface = interface
        self.read_pcap = read_pcap
        self.write_pcap = write_pcap
        self.max_packets = max_packets
        self.batch_size = batch_size
        self.max_rate = max_rate
        self.max_display = max_display

        self.telemetry = TrafficTelemetry()
        self.dissector = FastDissector()
        self.auditor = ThreatAuditor(self.queue_alert)
        self.reassembler = IPReassembler()
        self.store = PacketStore(max_packets=max_packets)

        self.pkt_queue: "queue.Queue[int]" = queue.Queue()
        self.alert_queue: "queue.Queue[str]" = queue.Queue()

        self.is_running = True
        self.paused = False
        self.current_theme = "btop_classic"
        self.current_pkt_idx: Optional[int] = None
        self.hex_search_query = ""
        self.display_filter = ""
        self.filter_fn: Callable[[Dict[str, Any]], bool] = compile_filter("")
        self._capture_thread: Optional[threading.Thread] = None

        self.setup_ui()

    # ------------------------------------------------------------------ UI
    def setup_ui(self) -> None:
        self._theme_attrs = {entry[0] for entry in THEMES[self.current_theme]}

        src = self.read_pcap or self.interface
        self.header = urwid.Text(f" 🦈 vimShark v{__version__} | {src} | Theme: {self.current_theme} | Buffer: 0/{self.max_packets}")
        self.header_attr = urwid.AttrMap(self.header, 'header')

        self.filter_edit = urwid.Edit(" Filter: ")
        urwid.connect_signal(self.filter_edit, 'change', self.on_filter_change)
        self.filter_attr = urwid.AttrMap(self.filter_edit, 'bg', 'text_focus')

        self.walker = urwid.SimpleFocusListWalker([])
        self.listbox = urwid.ListBox(self.walker)
        self.left_top = urwid.LineBox(urwid.Pile([
            ('pack', self.filter_attr),
            ('weight', 1, self.listbox)
        ]), title="Traffic Stream")

        self.tel_pkt = urwid.Text("Throughput: 0 p/s")
        self.tel_byte = urwid.Text("Bandwidth:  0 B/s")
        self.left_bottom = urwid.LineBox(urwid.Filler(urwid.Pile([self.tel_pkt, self.tel_byte])), title="Telemetry")
        self.left_pane = urwid.Pile([('weight', 4, self.left_top), ('weight', 1, self.left_bottom)])

        self.det_walker = urwid.SimpleFocusListWalker([urwid.Text("Select a packet...")])
        self.hex_walker = urwid.SimpleFocusListWalker([urwid.Text("")])
        self.alrt_walker = urwid.SimpleFocusListWalker([])

        self.right_pane = urwid.Pile([
            ('weight', 3, urwid.LineBox(urwid.ListBox(self.det_walker), title="Dissection")),
            ('weight', 2, urwid.LineBox(urwid.ListBox(self.hex_walker), title="Hex Dump")),
            ('weight', 1, urwid.LineBox(urwid.ListBox(self.alrt_walker), title="Security Alerts")),
        ])

        self.body = urwid.Columns([('weight', 3, self.left_pane), ('weight', 2, self.right_pane)], dividechars=1)
        self.footer = urwid.Text(" [Q]uit [T]heme [P]ause [F]ollow [S]earch Hex [E]xport [V]alidate [C]lear [/]Filter")
        self.root = urwid.Frame(urwid.AttrMap(self.body, 'bg'), header=self.header_attr,
                                 footer=urwid.AttrMap(self.footer, 'footer'))

    # --------------------------------------------------------------- alerts
    def queue_alert(self, msg: str) -> None:
        self.alert_queue.put(msg)

    # --------------------------------------------------------------- filter
    def on_filter_change(self, widget: urwid.Edit, text: str) -> None:
        self.display_filter = text
        self.filter_fn = compile_filter(text)
        self.refresh_display()

    def refresh_display(self) -> None:
        """Rebuild the visible row list from the PacketStore using the
        current filter. Only ever called from the main (UI) thread."""
        new_rows = []
        for idx in self.store.all_indices():
            item = self.store.get(idx)
            if item is None:
                continue
            _, summary, _ = item
            if self.filter_fn(summary):
                new_rows.append(self.build_row(idx, summary))
        if len(new_rows) > self.max_display:
            new_rows = new_rows[-self.max_display:]
        self.walker[:] = new_rows

    # ----------------------------------------------------------- row build
    def build_row(self, idx: int, summary: Dict[str, Any]) -> urwid.AttrMap:
        proto = summary['proto'].lower()
        attr = f"pkt_{proto}" if f"pkt_{proto}" in self._theme_attrs else "pkt_other"
        summ_text = summary['summary']
        if len(summ_text) > 60:
            summ_text = summ_text[:57] + "..."
        marker = " !" if summary.get('creds') else "  "
        line = f"#{idx:<5}{marker}| {summary['src']:<22} -> {summary['dst']:<22} | {summary['proto']:<7} | {summ_text}"
        btn = urwid.Button(line)
        btn._pkt_idx = idx  # lightweight int reference only - no raw bytes/dpkt objects
        urwid.connect_signal(btn, 'click', self.on_packet_click)
        return urwid.AttrMap(btn, attr, 'text_focus')

    # ------------------------------------------------------------- details
    def on_packet_click(self, btn: urwid.Button) -> None:
        idx = getattr(btn, '_pkt_idx', None)
        if idx is None:
            return
        self.current_pkt_idx = idx
        item = self.store.get(idx)
        if item is None:
            return
        raw, info, _ = item

        details = [
            urwid.Text(f"### Packet #{idx} Dissection ###"),
            urwid.Text(f"Length: {info.get('len', len(raw))} bytes"),
            urwid.Text("")
        ]

        # Core Layers
        for layer_name, fields in info.get('layers', []):
            details.append(urwid.AttrMap(urwid.Text(f"-- {layer_name} --"), 'header'))
            for k, v in fields.items():
                if k == 'data' or k.startswith('_') or callable(v):
                    continue
                sval = FastDissector._safe_str(v, 90)
                details.append(urwid.Text(f"  {k:<18}: {sval}"))

        # ==================== TLS SECTION ====================
        tls_info = info.get('tls_info', {})
        if tls_info and tls_info.get('handshake_type') != "Unknown":
            details.append(urwid.Text(""))
            details.append(urwid.AttrMap(urwid.Text("=== TLS / SSL ==="), 'pkt_tls'))

            if tls_info.get('version'):
                ver_text = tls_info['version']
                if tls_info.get('tls13'):
                    ver_text += " (TLS 1.3)"
                details.append(urwid.Text(f"  Version: {ver_text}"))

            if tls_info.get('cipher'):
                details.append(urwid.Text(f"  Cipher Suite: {tls_info['cipher']}"))

            if tls_info.get('ja3'):
                ja3_color = 'selected' if tls_info['ja3'] != "N/A" else 'pkt_other'
                details.append(urwid.AttrMap(
                    urwid.Text(f"  JA3 Fingerprint: {tls_info['ja3']}"), ja3_color))

            if tls_info.get('sni'):
                details.append(urwid.Text(f"  SNI: {tls_info['sni']}"))

            if tls_info.get('ocsp_stapled'):
                details.append(urwid.AttrMap(urwid.Text("  OCSP Stapling: Present"), 'pkt_http'))

            # Certificates
            certs = tls_info.get('certs', [])
            if certs:
                details.append(urwid.Text(""))
                details.append(urwid.AttrMap(
                    urwid.Text(f"=== Certificates ({len(certs)}) ==="), 'pkt_tls'))

                for i, cert in enumerate(certs):
                    header_color = 'pkt_icmp' if cert.get('is_expired') else 'pkt_tls'
                    details.append(urwid.AttrMap(
                        urwid.Text(f"  Cert #{i+1}:"), header_color))

                    details.append(urwid.Text(f"    Subject : {cert.get('subject', 'Unknown')}"))
                    details.append(urwid.Text(f"    Issuer  : {cert.get('issuer', 'Unknown')}"))
                    details.append(urwid.Text(f"    Valid   : {cert.get('not_before')} → {cert.get('not_after')}"))

                    if cert.get('is_expired'):
                        details.append(urwid.AttrMap(urwid.Text("    [!]  CERTIFICATE EXPIRED"), 'pkt_icmp'))

                    if cert.get('is_self_signed'):
                        details.append(urwid.AttrMap(urwid.Text("    [!]  Self-Signed Certificate"), 'pkt_icmp'))

                    if cert.get('san'):
                        details.append(urwid.Text(f"    SAN     : {', '.join(cert['san'][:5])}" +
                                                (" ..." if len(cert['san']) > 5 else "")))

                    fp = cert.get('fingerprint_sha256')
                    if fp:
                        details.append(urwid.Text(f"    SHA256  : {fp[:32]}..."))

                    if cert.get('ocsp_responders'):
                        details.append(urwid.Text(f"    OCSP    : {cert['ocsp_responders'][0]}"))

        # Credential warnings
        if info.get('creds'):
            details.append(urwid.Text(""))
            details.append(urwid.AttrMap(urwid.Text("!! POTENTIAL CREDENTIAL EXPOSURE !!"), 'pkt_icmp'))
            for c in info['creds']:
                details.append(urwid.Text(f"   • {c}"))

        self.det_walker[:] = details
        self.update_hex_view()

    def update_hex_view(self) -> None:
        if self.current_pkt_idx is None:
            self.hex_walker[:] = [urwid.Text("")]
            return
        item = self.store.get(self.current_pkt_idx)
        if not item: return
        raw, _, _ = item

        hd = self.dissector.get_hexdump(raw)
        lines = hd.splitlines()
        if not self.hex_search_query:
            self.hex_walker[:] = [urwid.Text(l) for l in lines]
            return

        query = self.hex_search_query.lower()
        new_hex_rows = []
        for line in lines:
            if query in line.lower():
                parts, last_end = [], 0
                lower_line = line.lower()
                start = lower_line.find(query)
                while start != -1:
                    parts.extend([line[last_end:start], ('selected', line[start:start+len(query)])])
                    last_end = start + len(query)
                    start = lower_line.find(query, last_end)
                parts.append(line[last_end:])
                new_hex_rows.append(urwid.Text(parts))
            else:
                new_hex_rows.append(urwid.Text(line))
        self.hex_walker[:] = new_hex_rows

    # --------------------------------------------------------------- capture
    def capture_loop(self) -> None:
        """Background thread: capture, dissect, store, enqueue index only."""
        try:
            if self.read_pcap:
                cap = pcapy.open_offline(self.read_pcap)
            else:
                cap = pcapy.open_live(self.interface, 65535, 1, 100)
        except Exception as e:
            logger.exception("capture init failed")
            self.queue_alert(f"Capture init error: {e}")
            return

        writer = None
        if self.write_pcap:
            try:
                writer = cap.dump_open(self.write_pcap)
            except Exception as e:
                logger.warning("pcap writer init failed: %s", e)
                self.queue_alert(f"PCAP write init failed: {e}")

        last_packet_time = 0.0
        min_interval = (1.0 / self.max_rate) if self.max_rate > 0 else 0.0

        while self.is_running:
            try:
                header, data = cap.next()
                if not data:
                    if self.read_pcap:
                        break
                    continue

                if writer is not None:
                    try:
                        writer.dump(header, data)
                    except Exception as e:
                        logger.warning("pcap write error, disabling writer: %s", e)
                        self.queue_alert(f"PCAP write error (disabled): {e}")
                        writer = None

                if self.paused:
                    continue

                if min_interval:
                    now = time.monotonic()
                    if now - last_packet_time < min_interval:
                        continue
                    last_packet_time = now

                summary = self.dissector.dissect(data)
                ts_sec, ts_usec = header.getts()
                ts = ts_sec + ts_usec / 1000000.0
                idx = self.store.add(data, summary, ts)
                self.pkt_queue.put(idx)
                self.telemetry.accumulate(len(data))
                self.auditor.audit_packet(data)
                
                # Handle IPv4 Reassembly
                eth = dpkt.ethernet.Ethernet(data)
                if isinstance(eth.data, dpkt.ip.IP):
                    ip = eth.data
                    if ip.off & (dpkt.ip.IP_MF | dpkt.ip.IP_OFFMASK):
                        full_payload = self.reassembler.process(ip)
                        if full_payload:
                            # Construct synthetic reassembled packet for the UI
                            ip.data = full_payload
                            ip.off = 0
                            ip.len = len(ip)
                            eth.data = ip
                            res_raw = bytes(eth)
                            res_summary = self.dissector.dissect(res_raw)
                            res_summary['summary'] = "[REASSEMBLED] " + res_summary['summary']
                            res_idx = self.store.add(res_raw, res_summary, ts)
                            self.pkt_queue.put(res_idx)

            except pcapy.PcapError:
                continue
            except Exception as e:
                logger.exception("capture loop error")
                self.queue_alert(f"Capture error: {e}")
                time.sleep(0.1)

    # ----------------------------------------------------------------- tick
    def ui_update_tick(self, loop: urwid.MainLoop, _user_data: Any) -> None:
        """Main-thread heartbeat: drains queues in batches, updates telemetry."""
        new_rows = []
        processed = 0
        while processed < self.batch_size:
            try:
                idx = self.pkt_queue.get_nowait()
            except queue.Empty:
                break
            item = self.store.get(idx)
            if item is not None:
                _, summary, _ = item
                if self.filter_fn(summary):
                    new_rows.append(self.build_row(idx, summary))
            processed += 1

        if new_rows:
            self.walker.extend(new_rows)
            overflow = len(self.walker) - self.max_display
            if overflow > 0:
                del self.walker[:overflow]

        while True:
            try:
                msg = self.alert_queue.get_nowait()
            except queue.Empty:
                break
            self.alrt_walker.append(urwid.Text(f" {msg}"))
            if len(self.alrt_walker) > 50:
                del self.alrt_walker[0]

        pr, br = self.telemetry.tick()
        self.tel_pkt.set_text(f"Throughput: {self.telemetry.format_unit(pr)} p/s  {self.telemetry.get_sparkline('p')}")
        self.tel_byte.set_text(f"Bandwidth:  {self.telemetry.format_unit(br, True)}/s  {self.telemetry.get_sparkline('b')}")

        status = "PAUSED" if self.paused else "LIVE"
        mode = "READ" if self.read_pcap else "CAPTURE"
        src = self.read_pcap or self.interface
        self.header.set_text(
            f" 🦈 vimShark v{__version__} | {src} | {mode} [{status}] | "
            f"Theme: {self.current_theme} | "
            f"Buffer: {len(self.store)}/{self.max_packets}"
        )

        loop.set_alarm_in(0.05, self.ui_update_tick)

    # --------------------------------------------------------------- input
    def handle_input(self, key: str) -> None:
        if key in ('q', 'Q', 'esc'):
            self.is_running = False
            raise urwid.ExitMainLoop()
        elif key in ('t', 'T'):
            self.cycle_theme()
        elif key in ('p', 'P'):
            self.paused = not self.paused
        elif key in ('c', 'C'):
            self.current_pkt_idx = None
            self.store.clear()
            self.walker[:] = []
            self.update_hex_view()
        elif key == '/':
            self.root.focus_position = 'body'
            self.body.focus_position = 0
            self.left_pane.focus_position = 0
            self.left_top.original_widget.focus_position = 0
        elif key in ('e', 'E'):
            self.show_export_modal()
        elif key in ('s', 'S'):
            self.show_hex_search_modal()
        elif key in ('v', 'V'):
            self.show_validation_modal()
        elif key in ('f', 'F'):
            self.follow_stream()

    def cycle_theme(self) -> None:
        names = list(THEMES.keys())
        cur = names.index(self.current_theme)
        self.current_theme = names[(cur + 1) % len(names)]
        self._theme_attrs = {entry[0] for entry in THEMES[self.current_theme]}
        self.loop.screen.register_palette(THEMES[self.current_theme])
        self.loop.screen.clear()
        self.refresh_display()

    # ------------------------------------------------------------- modals
    def show_validation_modal(self) -> None:
        edit = urwid.Edit("Target IP: ", "192.168.1.1")
        btn = urwid.Button("Dispatch Probe")
        cancel = urwid.Button("Cancel")

        def go(_b):
            self.auditor.active_probe(edit.get_edit_text(), self.interface)
            self.root.body = urwid.AttrMap(self.body, 'bg')

        def close(_b):
            self.root.body = urwid.AttrMap(self.body, 'bg')

        urwid.connect_signal(btn, 'click', go)
        urwid.connect_signal(cancel, 'click', close)
        overlay = urwid.Overlay(
            urwid.LineBox(urwid.Filler(urwid.Pile([edit, btn, cancel])), title="Active ARP Probe"),
            self.root.body, 'center', 40, 'middle', 9
        )
        self.root.body = overlay

    def show_hex_search_modal(self) -> None:
        edit = urwid.Edit("Search Hex/ASCII: ", self.hex_search_query)
        btn, clear, cancel = urwid.Button("Search"), urwid.Button("Clear"), urwid.Button("Cancel")

        def do_search(_b):
            self.hex_search_query = edit.get_edit_text()
            self.update_hex_view()
            self.root.body = urwid.AttrMap(self.body, 'bg')
        def do_clear(_b):
            self.hex_search_query = ""
            self.update_hex_view()
            self.root.body = urwid.AttrMap(self.body, 'bg')
        def close(_b):
            self.root.body = urwid.AttrMap(self.body, 'bg')

        urwid.connect_signal(btn, 'click', do_search)
        urwid.connect_signal(clear, 'click', do_clear)
        urwid.connect_signal(cancel, 'click', close)
        overlay = urwid.Overlay(
            urwid.LineBox(urwid.Filler(urwid.Pile([edit, urwid.Divider(), urwid.Columns([btn, clear, cancel])])), 
                          title="Hex Dump Search"),
            self.root.body, 'center', 50, 'middle', 9
        )
        self.root.body = overlay

    def show_export_modal(self) -> None:
        edit = urwid.Edit("Filename: ", "filtered_capture.pcap")
        btn = urwid.Button("Export PCAP")
        cancel = urwid.Button("Cancel")

        def do_export(_b):
            filename = edit.get_edit_text()
            self.export_filtered_packets(filename)
            self.root.body = urwid.AttrMap(self.body, 'bg')

        def close(_b):
            self.root.body = urwid.AttrMap(self.body, 'bg')

        urwid.connect_signal(btn, 'click', do_export)
        urwid.connect_signal(cancel, 'click', close)
        overlay = urwid.Overlay(
            urwid.LineBox(urwid.Filler(urwid.Pile([edit, urwid.Divider(), btn, cancel])), title="Export Filtered Traffic"),
            self.root.body, 'center', 45, 'middle', 9
        )
        self.root.body = overlay

    def export_filtered_packets(self, filename: str) -> None:
        try:
            count = 0
            with open(filename, 'wb') as f:
                writer = dpkt.pcap.Writer(f)
                for idx in self.store.all_indices():
                    item = self.store.get(idx)
                    if item:
                        raw, summary, ts = item
                        if self.filter_fn(summary):
                            writer.write_pkt(raw, ts)
                            count += 1
            self.queue_alert(f"Successfully exported {count} packets to {filename}")
        except Exception as e:
            self.queue_alert(f"Export failed: {e}")

    def _get_highlighted_markup(self, text: str, query: str) -> Any:
        """Helper to highlight search matches in text for urwid.Text markup."""
        if not query or query.lower() not in text.lower():
            return text
        parts = []
        last_end = 0
        l_text = text.lower()
        l_query = query.lower()
        q_len = len(query)
        idx = l_text.find(l_query)
        while idx != -1:
            if idx > last_end:
                parts.append(text[last_end:idx])
            parts.append(('selected', text[idx:idx + q_len]))
            last_end = idx + q_len
            idx = l_text.find(l_query, last_end)
        if last_end < len(text):
            parts.append(text[last_end:])
        return [p for p in parts if p != ""]

    def follow_stream(self) -> None:
        """Reassemble and display a TCP or UDP stream for the focused packet."""
        focus = self.listbox.focus
        if not focus:
            return
        btn = focus.base_widget
        idx = getattr(btn, '_pkt_idx', None)
        if idx is None:
            return
        item = self.store.get(idx)
        if item is None:
            return
        raw, _summary, _ = item

        try:
            eth = dpkt.ethernet.Ethernet(raw)
            if not isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
                return
            ip_pkt = eth.data
            
            if isinstance(ip_pkt.data, dpkt.tcp.TCP):
                proto_class = dpkt.tcp.TCP
                proto_label = "TCP"
            elif isinstance(ip_pkt.data, dpkt.udp.UDP):
                proto_class = dpkt.udp.UDP
                proto_label = "UDP"
            else:
                return
                
            transport = ip_pkt.data
            addr_set = {(ip_pkt.src, transport.sport), (ip_pkt.dst, transport.dport)}
            orig_src = (ip_pkt.src, transport.sport)

            src_str = ip_to_str(ip_pkt.src) if not isinstance(ip_pkt, dpkt.ip6.IP6) else ip6_to_str(ip_pkt.src)
            dst_str = ip_to_str(ip_pkt.dst) if not isinstance(ip_pkt, dpkt.ip6.IP6) else ip6_to_str(ip_pkt.dst)

            stream_rows: List[urwid.Widget] = [
                urwid.AttrMap(urwid.Text(
                    f"--- {proto_label} Stream {src_str}:{transport.sport} <-> {dst_str}:{transport.dport} (press q to close) ---"
                ), 'header'),
                urwid.Text(""),
            ]

            for i in self.store.all_indices():
                rec = self.store.get(i)
                if rec is None:
                    continue
                r, _, _ = rec
                try:
                    e = dpkt.ethernet.Ethernet(r)
                except Exception:
                    continue
                if not isinstance(e.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
                    continue
                p_ip, p_data = e.data, e.data.data
                if not isinstance(p_data, proto_class):
                    continue
                
                pair = {(p_ip.src, p_data.sport), (p_ip.dst, p_data.dport)}
                if pair != addr_set:
                    continue
                if not p_tcp.data:
                    continue
                
                # Extract raw bytes from payload (handles sub-parsed protocol objects)
                payload = p_data.data
                if not isinstance(payload, bytes):
                    try: payload = bytes(payload)
                    except: continue

                txt = "".join(chr(b) if 32 <= b <= 126 or b in (10, 13) else "." for b in payload)
                direction = '->' if (p_ip.src, p_data.sport) == orig_src else '<-'
                color = 'pkt_tcp' if direction == '->' else 'pkt_udp'
                
                markup = [f"[{direction}] "]
                highlighted = self._get_highlighted_markup(txt, self.hex_search_query)
                if isinstance(highlighted, list): markup.extend(highlighted)
                else: markup.append(highlighted)
                
                stream_rows.append(urwid.AttrMap(urwid.Text(markup), color))

            close_btn = urwid.Button("Close")
            parent = self.root.body

            def close(_b):
                self.root.body = parent

            urwid.connect_signal(close_btn, 'click', close)
            stream_rows.append(urwid.Text(""))
            stream_rows.append(close_btn)

            self.root.body = urwid.Overlay(
                urwid.LineBox(urwid.ListBox(urwid.SimpleListWalker(stream_rows)), title="Stream Follow"),
                parent, 'center', ('relative', 85), 'middle', ('relative', 85)
            )
        except Exception as e:
            logger.debug("follow_stream error: %s", e)

    # ----------------------------------------------------------------- 
    def run(self) -> None:
        if not self.read_pcap and os.getuid() != 0:
            print("[!] Live capture requires sudo/root.")
            sys.exit(1)

        self.loop = urwid.MainLoop(self.root, THEMES[self.current_theme], unhandled_input=self.handle_input)
        self.loop.screen.set_terminal_properties(colors=256)

        self._capture_thread = threading.Thread(target=self.capture_loop, daemon=True)
        self._capture_thread.start()

        self.loop.set_alarm_in(0.1, self.ui_update_tick)

        try:
            self.loop.run()
        except KeyboardInterrupt:
            pass
        finally:
            self.is_running = False
            if self._capture_thread is not None:
                self._capture_thread.join(timeout=1.0)
            logger.info("vimShark shut down cleanly")


# ==============================================================================
# ENTRY POINT
# ==============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=f"vimShark v{__version__}")
    parser.add_argument("-i", "--interface", default="eth0", help="Capture interface")
    parser.add_argument("-r", "--read", help="Read from a PCAP file instead of live capture")
    parser.add_argument("-o", "--output", help="Write captured packets to a PCAP file")
    parser.add_argument("-b", "--buffer", type=int, default=5000, help="Packet store capacity (ring buffer size)")
    parser.add_argument("--batch-size", type=int, default=100, help="Max packets drained from queue per UI tick")
    parser.add_argument("--max-rate", type=float, default=0.0, help="Throttle: max packets/sec to process (0 = unlimited)")
    parser.add_argument("--max-display", type=int, default=500, help="Max rows kept in the visible traffic list")
    parser.add_argument("--log-level", default="WARNING", choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                         help="Log verbosity (written to vimshark.log)")
    args = parser.parse_args()

    logger.setLevel(getattr(logging, args.log_level))

    app = vimSharkApp(
        interface=args.interface,
        read_pcap=args.read,
        write_pcap=args.output,
        max_packets=args.buffer,
        batch_size=args.batch_size,
        max_rate=args.max_rate,
        max_display=args.max_display,
    )
    app.run()
