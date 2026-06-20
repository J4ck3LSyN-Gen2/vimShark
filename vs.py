#!/usr/bin/env python3
import sys, os
# Support for local package installation (mitigation for sudo/venv conflicts)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path: 
    sys.path.insert(0, SCRIPT_DIR)
import time, threading, queue, re, socket, struct, argparse, logging, hashlib
from datetime import datetime, timezone
from collections import deque
from typing import Dict, List, Optional, Any, Tuple, Callable, Set, FrozenSet
try: import fcntl
except ImportError:
    fcntl = None
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
import urwid
import dpkt

# Optional dpkt submodules - not all builds ship every protocol module
try: import dpkt.ntp  # noqa: F401
except Exception as E: print(f"[^] Failed to import `dpkt.ntp`.\n\t-> [{str(E.__class__.__name__)}]:\n\t\t- {str(E)}")
try: import dpkt.icmp6  # noqa: F401
except Exception as E: print(f"[^] Failed to import `dpkt.icmp6`.\n\t-> [{str(E.__class__.__name__)}]:\n\t\t- {str(E)}") 
try: import dpkt.ssl  # noqa: F401
except Exception as E: print(f"[^] Failed to import `dpkt.ssl`.\n\t-> [{str(E.__class__.__name__)}]:\n\t\t- {str(E)}") 
try: import pcapy
except ImportError:
    print("[!] pcapy-ng is required: pip install pcapy-ng");sys.exit(1)

try:
    from scapy.all import ARP as ScapyARP, Ether as ScapyEther, srp as scapy_srp;SCAPY_AVAILABLE = True
except Exception as E: 
    SCAPY_AVAILABLE = False;print(f"[^] Failed to import `scapy` modules.\n\t-> [{str(E.__class__.__name__)}]:\n\t\t- {str(E)}")
__version__ = "0.2.4"
__author__ = "J4ck3LSyN"
logging.basicConfig(filename=os.path.join(SCRIPT_DIR, "vimshark.log"),level=logging.WARNING,format="%(asctime)s [%(levelname)s] %(message)s",)
logger = logging.getLogger("vimshark")
THEMES:Dict[str, List[Tuple]] = {
    "nullsecurityx":[
        ('bg', 'default', 'default', 'default', '#e0e0e0', '#0a0a0f'),          
        ('header', 'white', 'dark red', 'bold', '#ffffff', '#8b0000'),      
        ('footer', 'light gray', 'black', None, '#a8a8a8', '#1c1c1c'),            
        ('border', 'dark red', 'default', 'default', '#ff1a4d', '#0a0a0f'),
        ('selected', 'black', 'light red', 'standout', '#0a0a0f', '#ff2a2a'),
        ('pkt_tcp', 'light cyan', 'default', 'default', '#00f0ff', '#0a0a0f'),    
        ('pkt_udp', 'light magenta', 'default', 'default', '#ff00aa', '#0a0a0f'),
        ('pkt_arp', 'yellow', 'default', 'default', '#ffd700', '#0a0a0f'),
        ('pkt_dns', 'light cyan', 'default', 'default', '#40e0ff', '#0a0a0f'),
        ('pkt_icmp', 'light red', 'default', 'default', '#ff3333', '#0a0a0f'),
        ('pkt_icmp6', 'light red', 'default', 'default', '#ff3333', '#0a0a0f'),
        ('pkt_http', 'light green', 'default', 'default', '#00ff9f', '#0a0a0f'),
        ('pkt_tls', 'light blue', 'default', 'default', '#00b7ff', '#0a0a0f'),
        ('pkt_ntp', 'yellow', 'default', 'default', '#ffd700', '#0a0a0f'),
        ('pkt_other', 'light gray', 'default', 'default', '#777777', '#0a0a0f'),
        ('spark_bar', 'light red', 'default', None, '#ff2a2a', '#0a0a0f'),
        ('text_focus', 'black', 'light red', None, '#0a0a0f', '#ff2a2a'),
        ('warn', 'light red', 'default', 'bold', '#ff5555', '#0a0a0f'),
        ('good', 'light green', 'default', 'bold', '#00ff9f', '#0a0a0f'),
        ('ja3', 'black', 'yellow', 'standout', '#0a0a0f', '#ffd700'),
        ('dim', 'dark gray', 'default', 'default', '#555555', '#0a0a0f'),
    ],
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
        ('warn', 'light red', 'default', 'bold', '#eb6f92', '#1a1625'),
        ('good', 'light green', 'default', 'bold', '#9ccfd8', '#1a1625'),
        ('ja3', 'black', 'yellow', 'standout', '#1a1625', '#f6c177'),
        ('dim', 'dark gray', 'default', 'default', '#6e6a86', '#1a1625'),
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
        ('warn', 'light red', 'default', 'bold', '#ff5f9e', '#0d0a1f'),
        ('good', 'light green', 'default', 'bold', '#9dffb0', '#0d0a1f'),
        ('ja3', 'black', 'yellow', 'standout', '#0d0a1f', '#ffe066'),
        ('dim', 'dark gray', 'default', 'default', '#8e7fb5', '#0d0a1f'),
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
        ('warn', 'light red', 'default', 'bold', '#ff7a93', '#120e1e'),
        ('good', 'light green', 'default', 'bold', '#b3ffd9', '#120e1e'),
        ('ja3', 'black', 'yellow', 'standout', '#120e1e', '#ffe9a8'),
        ('dim', 'dark gray', 'default', 'default', '#8c80ad', '#120e1e'),
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
        ('warn', 'light red', 'default', 'bold', '#ff5555', '#0f1419'),
        ('good', 'light green', 'default', 'bold', '#00af5f', '#0f1419'),
        ('ja3', 'black', 'yellow', 'standout', '#0f1419', '#ffaf00'),
        ('dim', 'dark gray', 'default', 'default', '#8a95a5', '#0f1419'),
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
        ('warn', 'light red', 'default', 'bold', '#fb4934', '#282828'),
        ('good', 'light green', 'default', 'bold', '#b8bb26', '#282828'),
        ('ja3', 'black', 'yellow', 'standout', '#282828', '#fabd2f'),
        ('dim', 'dark gray', 'default', 'default', '#928374', '#282828'),
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
        ('warn', 'light red', 'default', 'bold', '#ff5555', '#282a36'),
        ('good', 'light green', 'default', 'bold', '#50fa7b', '#282a36'),
        ('ja3', 'black', 'yellow', 'standout', '#282a36', '#f1fa8c'),
        ('dim', 'dark gray', 'default', 'default', '#6272a4', '#282a36'),
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
        ('warn', 'light red', 'default', 'bold', '#ff0000', '#000b1e'),
        ('good', 'light green', 'default', 'bold', '#00ff00', '#000b1e'),
        ('ja3', 'black', 'yellow', 'standout', '#000b1e', '#ffff00'),
        ('dim', 'dark gray', 'default', 'default', '#00ffff', '#000b1e'),
    ],
}

# ==============================================================================
# UTILITIES
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
    if sys.platform != 'linux' or fcntl is None:
        return b'\x00' * 6
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        info = fcntl.ioctl(s.fileno(), _SIOCGIFHWADDR, struct.pack('256s', iface[:15].encode()))
        return info[18:24]
    except Exception as e:
        logger.debug("get_iface_mac failed: %s", e)
        return b'\x00' * 6
    finally:
        s.close()


def get_iface_ip(iface: str) -> bytes:
    """Return the raw 4-byte IPv4 address for an interface via ioctl."""
    if sys.platform != 'linux' or fcntl is None:
        return b'\x00' * 4
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        info = fcntl.ioctl(s.fileno(), _SIOCGIFADDR, struct.pack('256s', iface[:15].encode()))
        return info[20:24]
    except Exception as e:
        logger.debug("get_iface_ip failed: %s", e)
        return b'\x00' * 4
    finally:
        s.close()


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


def fmt_ts(iso_dt: Optional[str]) -> str:
    """Pretty-format an ISO datetime string for display, tolerating None."""
    if not iso_dt:
        return "Unknown"
    return iso_dt.replace("T", " ").split("+")[0].split(".")[0] + "Z"

    return iso_dt.replace("T", " ").split("+")[0].split(".")[0] + "Z"


# ==============================================================================
# TRAFFIC TELEMETRY
# ==============================================================================

class TrafficTelemetry:
    """Tracks rolling packet/byte rates with EMA smoothing and sparkline history."""

    def __init__(self, max_history: int = 40):
        self.packet_history: deque = deque([0] * max_history, maxlen=max_history)
        self.byte_history: deque = deque([0] * max_history, maxlen=max_history)
        self.p_acc = 0
        self.b_acc = 0
        self.last_tick = time.time()
        self.blocks = ' ▂▃▄▅▆▇█'
        self.p_rate = 0.0
        self.b_rate = 0.0
        self.total_packets = 0
        self.total_bytes = 0

    def accumulate(self, length: int) -> None:
        self.p_acc += 1
        self.b_acc += length
        self.total_packets += 1
        self.total_bytes += length

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
            if val >= 1_000_000:
                return f"{val / 1_000_000:.1f}M"
            if val >= 1_000:
                return f"{val / 1_000:.1f}K"
            return str(int(val))
        for unit in ('', 'K', 'M', 'G', 'T'):
            if val < 1024:
                return f"{val:.1f}{unit}B" if unit else f"{int(val)}B"
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
    cross-thread / dangling-reference patterns that caused crashes."""

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
# DISSECTION ENGINE (v0.3 - Enhanced TLS + JA3/JA3S + Certificate Intelligence)
# ==============================================================================

# GREASE values (RFC 8701) must be ignored when computing JA3/JA3S
_GREASE_VALUES: FrozenSet[int] = frozenset({
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
})

# TLS extension numbers worth recognizing for SNI / ALPN / supported groups, etc.
_EXT_SERVER_NAME = 0
_EXT_SUPPORTED_GROUPS = 10
_EXT_EC_POINT_FORMATS = 11
_EXT_ALPN = 16
_EXT_SUPPORTED_VERSIONS = 43

_TLS_VERSION_NAMES: Dict[int, str] = {
    0x0300: "SSLv3",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

# IANA cipher‑suite names (partial – enough for common traffic)
_CIPHER_SUITES: Dict[int, str] = {
    0x0000: "TLS_NULL_WITH_NULL_NULL",
    0x0001: "TLS_RSA_WITH_NULL_MD5",
    0x0002: "TLS_RSA_WITH_NULL_SHA",
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",
    0x002f: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x003c: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x009c: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009d: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0xc02f: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xc030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xc02b: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xc02c: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
}


class FastDissector:
    """High-performance, multi-protocol packet dissector with robust TLS
    parsing, JA3/JA3S fingerprinting, enriched certificate details, and
    lightweight credential leakage detection."""

    _CRED_PATTERNS: List[Tuple[re.Pattern, str]] = [
        (re.compile(rb'(?i)authorization:\s*basic\s+\S+'), 'HTTP Basic Auth'),
        (re.compile(rb'(?i)authorization:\s*bearer\s+\S+'), 'Bearer token'),
        (re.compile(rb'(?i)\b(pass(word)?|pwd|passwd|secret|token)\s*[:=]\s*[^&\s]+'), 'Cleartext credential'),
        (re.compile(rb'(?i)cookie:[^\r\n]*sess[^\r\n]*=\S+'), 'Session cookie'),
        (re.compile(rb'(?i)^USER\s+\S+', re.MULTILINE), 'FTP/IMAP/SMTP USER'),
        (re.compile(rb'(?i)^PASS\s+\S+', re.MULTILINE), 'FTP/IMAP/SMTP PASS'),
        (re.compile(rb'(?i)api[-_]?key[:=]\s*\S+'), 'API Key'),
    ]

    # --------------------------------------------------------------- helpers

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
        flag_map = (
            (dpkt.tcp.TH_FIN, 'F'), (dpkt.tcp.TH_SYN, 'S'), (dpkt.tcp.TH_RST, 'R'),
            (dpkt.tcp.TH_PUSH, 'P'), (dpkt.tcp.TH_ACK, 'A'), (dpkt.tcp.TH_URG, 'U'),
            (dpkt.tcp.TH_ECE, 'E'), (dpkt.tcp.TH_CWR, 'C'),
        )
        return ''.join(c for bit, c in flag_map if flags & bit)

    @staticmethod
    def _safe_str(val: Any, max_len: int = 120) -> str:
        """Convert any field value to a clean, readable string."""
        if val is None:
            return "None"
        if hasattr(val, '__class__') and val.__class__.__module__.startswith('dpkt') \
                and not isinstance(val, (bytes, bytearray)):
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

    # ====================== TLS EXTENSION PARSING ======================

    @staticmethod
    def _parse_extension_data(ext_type: int, data: bytes, ja3_info: Dict[str, Any]) -> None:
        """Mutates ja3_info with details extracted from a single TLS extension."""
        try:
            if ext_type == _EXT_SERVER_NAME:  # SNI
                # struct: 2-byte list len, then [1-byte type, 2-byte len, name...]
                if len(data) < 2:
                    return
                pos = 2
                while pos + 3 <= len(data):
                    name_type = data[pos]
                    name_len = struct.unpack('!H', data[pos + 1:pos + 3])[0]
                    name_val = data[pos + 3:pos + 3 + name_len]
                    if name_type == 0:  # host_name
                        ja3_info["sni"] = name_val.decode('utf-8', errors='replace')
                    pos += 3 + name_len

            elif ext_type == _EXT_SUPPORTED_GROUPS:  # elliptic curves
                if len(data) >= 2:
                    list_len = struct.unpack('!H', data[:2])[0]
                    for i in range(2, min(2 + list_len, len(data)) - 1, 2):
                        val = struct.unpack('!H', data[i:i + 2])[0]
                        if val not in _GREASE_VALUES:
                            ja3_info["curves"].append(val)

            elif ext_type == _EXT_EC_POINT_FORMATS:
                if len(data) >= 1:
                    list_len = data[0]
                    for i in range(1, min(1 + list_len, len(data))):
                        ja3_info["points"].append(data[i])

            elif ext_type == _EXT_ALPN:
                # struct: 2-byte list len, then [1-byte len, proto...]
                if len(data) >= 2:
                    list_len = struct.unpack('!H', data[:2])[0]
                    pos = 2
                    protos = []
                    end = min(2 + list_len, len(data))
                    while pos < end:
                        plen = data[pos]
                        proto = data[pos + 1:pos + 1 + plen]
                        protos.append(proto.decode('utf-8', errors='replace'))
                        pos += 1 + plen
                    ja3_info["alpn"] = protos

            elif ext_type == _EXT_SUPPORTED_VERSIONS:
                if len(data) >= 1:
                    list_len = data[0]
                    versions = []
                    for i in range(1, min(1 + list_len, len(data)) - 1, 2):
                        v = struct.unpack('!H', data[i:i + 2])[0]
                        if v not in _GREASE_VALUES:
                            versions.append(v)
                    if versions:
                        ja3_info["supported_versions"] = versions
                        # Highest offered version is the best signal for TLS1.3
                        if max(versions) == 0x0304:
                            ja3_info["client_tls13"] = True

        except Exception as e:
            logger.debug("extension parse error (type=%s): %s", ext_type, e)

    # ====================== JA3 / JA3S FINGERPRINTING ======================

    @staticmethod
    def _parse_ja3_client_hello(handshake) -> Dict[str, Any]:
        """Extract data and compute the JA3 fingerprint from a ClientHello."""
        ja3_info: Dict[str, Any] = {
            "ja3": "N/A", "ciphers": [], "extensions": [], "curves": [],
            "points": [], "sni": None, "alpn": [], "supported_versions": [],
            "client_tls13": False,
        }

        try:
            ciphers = getattr(handshake, 'ciphersuites', getattr(handshake, 'cipher_suites', []))
            ja3_info["ciphers"] = [
                c for c in (getattr(item, 'code', item) for item in ciphers)
                if c not in _GREASE_VALUES
            ]

            for ext in getattr(handshake, 'extensions', []):
                ext_type = getattr(ext, 'type', None)
                if ext_type is None or ext_type in _GREASE_VALUES:
                    continue
                ja3_info["extensions"].append(ext_type)
                FastDissector._parse_extension_data(ext_type, getattr(ext, 'data', b''), ja3_info)

            ja3_str = (
                f"{handshake.version},"
                f"{'-'.join(map(str, ja3_info['ciphers']))},"
                f"{'-'.join(map(str, ja3_info['extensions']))},"
                f"{'-'.join(map(str, ja3_info['curves']))},"
                f"{'-'.join(map(str, ja3_info['points']))}"
            )
            ja3_info["ja3"] = hashlib.md5(ja3_str.encode('utf-8')).hexdigest()
            ja3_info["ja3_str"] = ja3_str

        except Exception as e:
            logger.debug("JA3 parsing error: %s", e)

        return ja3_info

    @staticmethod
    def _parse_ja3s_server_hello(handshake) -> Dict[str, Any]:
        """Extract data and compute the JA3S fingerprint from a ServerHello.

        JA3S format: SSLVersion,Cipher,SSLExtension
        (server responses don't echo curves/point formats).
        """
        ja3s_info: Dict[str, Any] = {"ja3s": "N/A", "extensions": [], "cipher": None}

        try:
            cipher_obj = getattr(handshake, 'ciphersuite', getattr(handshake, 'cipher_suite', None))
            cipher_code = getattr(cipher_obj, 'code', cipher_obj)
            ja3s_info["cipher"] = cipher_code

            for ext in getattr(handshake, 'extensions', []):
                ext_type = getattr(ext, 'type', None)
                if ext_type is None or ext_type in _GREASE_VALUES:
                    continue
                ja3s_info["extensions"].append(ext_type)

            ja3s_str = (
                f"{handshake.version},"
                f"{cipher_code if cipher_code is not None else ''},"
                f"{'-'.join(map(str, ja3s_info['extensions']))}"
            )
            ja3s_info["ja3s"] = hashlib.md5(ja3s_str.encode('utf-8')).hexdigest()
            ja3s_info["ja3s_str"] = ja3s_str

        except Exception as e:
            logger.debug("JA3S parsing error: %s", e)

        return ja3s_info

    # ====================== CERTIFICATE PARSING ======================

    @staticmethod
    def _parse_tls_cert(cert_der: bytes) -> Dict[str, Any]:
        """Enhanced X.509 certificate parsing using `cryptography` if available,
        falling back to a SHA256 fingerprint-only summary otherwise."""
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
            "signature_algorithm": None,
            "is_expired": False,
            "is_not_yet_valid": False,
            "is_self_signed": False,
            "days_remaining": None,
        }

        if not cert_der:
            return info

        try:
            if CRYPTOGRAPHY_AVAILABLE:
                cert = x509.load_der_x509_certificate(cert_der, default_backend())

                info["subject"] = cert.subject.rfc4514_string()
                info["issuer"] = cert.issuer.rfc4514_string()
                info["serial"] = hex(cert.serial_number)

                # Validity period – try the modern UTC-aware accessors first,
                # falling back to the naive datetime properties on older releases.
                try:
                    not_before = cert.not_valid_before_utc
                    not_after = cert.not_valid_after_utc
                except AttributeError:
                    not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
                    not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

                info["not_before"] = not_before.isoformat()
                info["not_after"] = not_after.isoformat()

                info["fingerprint_sha256"] = cert.fingerprint(hashes.SHA256()).hex()
                info["fingerprint_sha1"] = cert.fingerprint(hashes.SHA1()).hex()

                try:
                    info["signature_algorithm"] = cert.signature_hash_algorithm.name
                except Exception:
                    pass

                # Subject Alternative Names
                try:
                    san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                    info["san"] = [str(name.value) for name in san_ext.value]
                except x509.ExtensionNotFound:
                    pass
                except Exception as e:
                    logger.debug("SAN parse error: %s", e)

                # Public key algorithm + size
                try:
                    pub = cert.public_key()
                    pk_name = pub.__class__.__name__
                    key_size = getattr(pub, 'key_size', None)
                    info["pubkey_algorithm"] = f"{pk_name} ({key_size} bit)" if key_size else pk_name
                except Exception:
                    pass

                # CRL distribution points + OCSP responders
                for ext in cert.extensions:
                    try:
                        if isinstance(ext.value, x509.CRLDistributionPoints):
                            for dp in ext.value:
                                if dp.full_name:
                                    for point in dp.full_name:
                                        if isinstance(point, x509.UniformResourceIdentifier):
                                            info["crl_distribution_points"].append(point.value)
                        if isinstance(ext.value, x509.AuthorityInformationAccess):
                            for ad in ext.value:
                                if ad.access_method == x509.oid.AuthorityInformationAccessOID.OCSP:
                                    if isinstance(ad.access_location, x509.UniformResourceIdentifier):
                                        info["ocsp_responders"].append(ad.access_location.value)
                    except Exception as e:
                        logger.debug("extension scan error: %s", e)

                # Validity / trust checks
                now = datetime.now(timezone.utc)
                info["is_expired"] = not_after < now
                info["is_not_yet_valid"] = not_before > now
                info["is_self_signed"] = cert.subject == cert.issuer
                info["days_remaining"] = int((not_after - now).total_seconds() // 86400)

            else:
                # Fallback – just hash the raw DER
                info["fingerprint_sha256"] = hashlib.sha256(cert_der).hexdigest()
                info["fingerprint_sha1"] = hashlib.sha1(cert_der).hexdigest()
                info["subject"] = "Install 'cryptography' for full parsing"

        except Exception as e:
            logger.debug("Cert parse error: %s", e)
            if not info["fingerprint_sha256"]:
                info["fingerprint_sha256"] = hashlib.sha256(cert_der).hexdigest()

        return info

    # ====================== TLS HANDSHAKE PARSING ======================

    @staticmethod
    def _parse_tls_handshake(tcp_payload: bytes) -> Dict[str, Any]:
        """Robust TLS record/handshake parser with JA3/JA3S support.

        Handles multi‑record reads, multiple handshake messages per record,
        and degrades gracefully on TLS 1.3 (where Certificate is encrypted
        and thus invisible post‑handshake) and on fragmented streams (where
        a single TCP segment may contain a partial handshake message).
        """
        result: Dict[str, Any] = {
            "certs": [],
            "sni": None,
            "alpn": [],
            "version": None,
            "version_name": None,
            "cipher": None,
            "cipher_name": None,
            "ja3": None,
            "ja3_info": {},
            "ja3s": None,
            "ja3s_info": {},
            "ocsp_stapled": False,
            "handshake_type": "Unknown",
            "tls13": False,
            "alert": None,
        }

        if not tcp_payload or len(tcp_payload) < 5:
            return result

        try:
            # Initial sanity check: TLS record content types are 20‑23
            if tcp_payload[0] not in (20, 21, 22, 23):
                return result

            tls = dpkt.ssl.TLS(tcp_payload)

            # Baseline version from the record header to avoid 'None'
            if hasattr(tls, 'version'):
                result["version"] = tls.version
                result["version_name"] = _TLS_VERSION_NAMES.get(tls.version, f"0x{tls.version:04x}")

            if hasattr(tls, 'type'):
                if tls.type == 20:
                    result["handshake_type"] = "ChangeCipherSpec"
                elif tls.type == 21:
                    result["handshake_type"] = "Alert"
                elif tls.type == 23:
                    result["handshake_type"] = "AppData"

            records = getattr(tls, 'records', None) or [tls]

            for record in records:
                rtype = getattr(record, 'type', None)

                if rtype == 21:  # Alert
                    try:
                        adata = record.data
                        if len(adata) >= 2:
                            level, desc = adata[0], adata[1]
                            result["alert"] = f"level={level} desc={desc}"
                    except Exception:
                        pass
                    continue

                if rtype != 22:  # Not a Handshake record
                    continue

                # A record can contain multiple handshake messages
                # (e.g. ServerHello + Certificate + ServerHelloDone)
                h_data = record.data
                while len(h_data) >= 4:
                    try:
                        handshake = dpkt.ssl.TLSHandshake(h_data)
                    except (dpkt.NeedData, dpkt.UnpackError):
                        # Fragmented handshake message split across TCP segments.
                        break

                    hs_type = getattr(handshake, 'type', None)
                    h_len = getattr(handshake, 'length', 0)

                    if len(h_data) < 4 + h_len:
                        # Truncated – message continues in a later segment.
                        if hs_type == 1:
                            result["handshake_type"] = "ClientHello (fragmented)"
                        elif hs_type == 2:
                            result["handshake_type"] = "ServerHello (fragmented)"
                        elif hs_type == 11:
                            result["handshake_type"] = "Certificate (fragmented)"
                        break

                    if hs_type == 1:  # ClientHello
                        result["handshake_type"] = "ClientHello"
                        inner = handshake.data
                        result["version"] = inner.version
                        result["version_name"] = _TLS_VERSION_NAMES.get(inner.version, f"0x{inner.version:04x}")
                        ja3_data = FastDissector._parse_ja3_client_hello(inner)
                        result["ja3"] = ja3_data["ja3"]
                        result["ja3_info"] = ja3_data
                        result["sni"] = ja3_data["sni"]
                        result["alpn"] = ja3_data["alpn"]
                        if ja3_data.get("client_tls13"):
                            result["tls13"] = True

                    elif hs_type == 2:  # ServerHello
                        result["handshake_type"] = "ServerHello"
                        inner = handshake.data
                        if hasattr(inner, 'version'):
                            result["version"] = inner.version
                            result["version_name"] = _TLS_VERSION_NAMES.get(inner.version, f"0x{inner.version:04x}")
                            if inner.version == 0x0304:
                                result["tls13"] = True
                        ja3s_data = FastDissector._parse_ja3s_server_hello(inner)
                        result["ja3s"] = ja3s_data["ja3s"]
                        result["ja3s_info"] = ja3s_data
                        cipher = ja3s_data.get("cipher")
                        if cipher is not None:
                            result["cipher"] = cipher
                            result["cipher_name"] = f"0x{cipher:04x}"

                    elif hs_type == 11:  # Certificate
                        result["handshake_type"] = "Certificate"
                        inner = handshake.data
                        for cert_der in getattr(inner, 'certificates', []):
                            if isinstance(cert_der, (bytes, bytearray)) and len(cert_der) > 0:
                                parsed = FastDissector._parse_tls_cert(cert_der)
                                result["certs"].append(parsed)

                    elif hs_type == 22:  # CertificateStatus (OCSP Stapling)
                        result["ocsp_stapled"] = True
                        result["handshake_type"] = "CertificateStatus (OCSP)"

                    elif hs_type == 14:  # ServerHelloDone
                        if result["handshake_type"] == "Unknown":
                            result["handshake_type"] = "ServerHelloDone"

                    elif result["handshake_type"] in ("Unknown", "Handshake"):
                        result["handshake_type"] = f"Handshake(type={hs_type})"

                    h_data = h_data[4 + h_len:]

        except (dpkt.NeedData, dpkt.UnpackError) as e:
            logger.debug("TLS NeedData/UnpackError (likely fragmented): %s", e)
        except Exception as e:
            logger.debug("TLS handshake parse error: %s", e)

        return result

    # ====================== LAYER WALKING ======================

    @staticmethod
    def _dissect_layer(layer: Any, depth: int = 0) -> List[Tuple[str, Dict[str, Any]]]:
        """Recursively dissect nested protocol layers for the detail view."""
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
                    if attr.startswith('_') or attr in ('data', 'unpack', 'pack', 'off', 'sum'):
                        continue
                    val = getattr(layer, attr, None)
                    if not callable(val):
                        fields[attr] = val

            layers.append((layer_name, fields))

            payload = getattr(layer, 'data', None)
            if payload is not None and hasattr(payload, '__class__') \
                    and payload.__class__.__module__.startswith('dpkt'):
                layers.extend(FastDissector._dissect_layer(payload, depth + 1))

        except Exception as e:
            logger.debug("layer dissection error: %s", e)

        return layers

    # ====================== MAIN ENTRY POINT ======================

    @staticmethod
    def dissect(raw_pkt: bytes) -> Dict[str, Any]:
        """Main dissection entry point. Returns a flat summary dict consumed
        by the UI for row rendering, filtering, and the detail pane."""
        res: Dict[str, Any] = {
            "proto": "OTHER", "src": "N/A", "dst": "N/A", "summary": "Unknown Frame",
            "len": len(raw_pkt), "layers": [], "creds": [], "ports": [], "tls_info": {},
        }

        try:
            eth = dpkt.ethernet.Ethernet(raw_pkt)
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
                    res["summary"] = (
                        f"TCP {tcp.sport}->{tcp.dport} [{flagstr}] "
                        f"Seq={tcp.seq} Ack={tcp.ack} Len={len(tcp.data or b'')}"
                    )

                    if tcp.data:
                        res["creds"] = FastDissector._scan_credentials(tcp.data)

                    # HTTP
                    if tcp.dport in (80, 8080) or tcp.sport in (80, 8080):
                        try:
                            data = tcp.data
                            http_cls = dpkt.http.Response if data.startswith(b'HTTP/') else dpkt.http.Request
                            http = http_cls(data)
                            res["proto"] = "HTTP"
                            method_or_ver = getattr(http, 'method', http.version)
                            uri_or_status = getattr(http, 'uri', getattr(http, 'status', ''))
                            res["summary"] = f"HTTP {method_or_ver} {uri_or_status}"
                            tcp.data = http
                        except Exception:
                            pass

                    # TLS (port‑agnostic)
                    if tcp.data and tcp.data[:1] and tcp.data[0] in (20, 21, 22, 23):
                        res["proto"] = "TLS"
                        tls_info = FastDissector._parse_tls_handshake(tcp.data or b'')
                        res["tls_info"] = tls_info

                        h_type = tls_info.get('handshake_type', 'Data')
                        ver = tls_info.get('version_name') or '?'

                        extra_bits = []
                        if tls_info.get('sni'):
                            extra_bits.append(f"SNI:{tls_info['sni']}")
                        if tls_info.get('ja3') and tls_info['ja3'] != "N/A":
                            extra_bits.append(f"JA3:{tls_info['ja3'][:12]}")
                        if tls_info.get('ja3s') and tls_info['ja3s'] != "N/A":
                            extra_bits.append(f"JA3S:{tls_info['ja3s'][:12]}")
                        if tls_info.get('certs'):
                            extra_bits.append(f"Certs:{len(tls_info['certs'])}")
                        if tls_info.get('alert'):
                            extra_bits.append(f"ALERT({tls_info['alert']})")

                        extra = (" " + " ".join(extra_bits)) if extra_bits else ""
                        res["summary"] = f"TLS {h_type} {tcp.sport}->{tcp.dport} v{ver}{extra}"

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

                elif isinstance(ip_pkt.data, dpkt.icmp.ICMP):
                    icmp = ip_pkt.data
                    res["proto"] = "ICMP"
                    res["summary"] = f"ICMP Type={icmp.type} Code={icmp.code}"

                elif hasattr(dpkt, 'icmp6') and isinstance(ip_pkt.data, dpkt.icmp6.ICMP6):
                    icmp6 = ip_pkt.data
                    res["proto"] = "ICMPv6"
                    res["summary"] = f"ICMPv6 Type={icmp6.type} Code={icmp6.code}"

            elif eth.type == 0x8100:
                res["proto"] = "VLAN"
                res["summary"] = "802.1Q VLAN Frame"

            # Build the layer tree once, after any in‑place protocol enrichment
            res["layers"] = FastDissector._dissect_layer(eth)

        except Exception as e:
            logger.debug("dissect error: %s", e)

        return res

    @staticmethod
    def get_hexdump(data: bytes, max_bytes: int = 1024) -> str:
        """Generate a classic offset/hex/ASCII hexdump."""
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
    """Stateful IPv4 fragmentation reassembler with expiry of stale buffers."""

    def __init__(self, max_age: float = 30.0):
        self.fragments: Dict[Tuple, Dict[int, bytes]] = {}
        self.finished: Dict[Tuple, int] = {}
        self.timestamps: Dict[Tuple, float] = {}
        self.max_age = max_age

    def process(self, ip: "dpkt.ip.IP") -> Optional[bytes]:
        now = time.time()
        # Clean up expired buffers
        expired = [k for k, ts in self.timestamps.items() if now - ts > self.max_age]
        for k in expired:
            self._clear(k)

        # Fragment offset is in 8‑byte units
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
                else:
                    return None  # Still missing pieces
            self._clear(key)
            return b"".join(parts)
        return None

    def _clear(self, key) -> None:
        self.fragments.pop(key, None)
        self.finished.pop(key, None)
        self.timestamps.pop(key, None)


# ==============================================================================
# FLOW TRACKER
# ==============================================================================

class FlowTracker:
    """Lightweight bidirectional flow table. Tracks per‑flow packet/byte
    counters and last‑seen timestamps so the UI can surface "top talkers"
    and basic conversation hints without a full state machine."""

    def __init__(self, max_flows: int = 2000):
        self.flows: Dict[FrozenSet, Dict[str, Any]] = {}
        self.max_flows = max_flows

    def update(self, summary: Dict[str, Any], ts: float) -> Optional[Dict[str, Any]]:
        src, dst, proto = summary.get('src'), summary.get('dst'), summary.get('proto')
        if not src or not dst or proto in ('ARP', 'OTHER'):
            return None

        key = frozenset((src, dst))
        flow = self.flows.get(key)
        if flow is None:
            if len(self.flows) >= self.max_flows:
                # Evict the oldest flow to bound memory use
                oldest_key = min(self.flows, key=lambda k: self.flows[k]['last_seen'])
                self.flows.pop(oldest_key, None)
            flow = {
                "endpoints": (src, dst), "proto": proto,
                "packets": 0, "bytes": 0,
                "first_seen": ts, "last_seen": ts,
            }
            self.flows[key] = flow

        flow["packets"] += 1
        flow["bytes"] += summary.get('len', 0)
        flow["last_seen"] = ts
        return flow

    def top_flows(self, n: int = 10) -> List[Dict[str, Any]]:
        return sorted(self.flows.values(), key=lambda f: f['bytes'], reverse=True)[:n]

    def clear(self) -> None:
        self.flows.clear()


# ==============================================================================
# FILTER EXPRESSIONS
# ==============================================================================

_COND_RE = re.compile(r'^\s*(\w+)\s*(==|!=)\s*(\S+)\s*$')


def _get_field(summary: Dict[str, Any], field: str) -> Any:
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
    if field == 'sni':
        return (summary.get('tls_info') or {}).get('sni')
    if field == 'ja3':
        return (summary.get('tls_info') or {}).get('ja3')
    if field == 'ja3s':
        return (summary.get('tls_info') or {}).get('ja3s')
    if field == 'cred':
        return 'yes' if summary.get('creds') else 'no'
    return None


def _compile_expr_filter(expr: str) -> Callable[[Dict[str, Any]], bool]:
    """Compile a `field==value`, `field!=value`, free‑text, `&&`, `||`
    expression into a predicate. Recognized fields: proto, src, dst, srcip,
    dstip, sport, dport, port, len, sni, ja3, ja3s, cred."""
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
                    text = (
                        f"{summary.get('summary', '')} {summary.get('proto', '')} "
                        f"{summary.get('src', '')} {summary.get('dst', '')}"
                    ).lower()
                    cond = val in text
                else:
                    actual = _get_field(summary, field)
                    if actual is None:
                        cond = False
                    elif isinstance(actual, list):
                        cond = any(str(a).lower() == val.lower() for a in actual)
                    else:
                        cond = val.lower() in str(actual).lower()
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
    """Lightweight passive + active security checks with improved port scan detection."""

    def __init__(self, alert_cb: Callable[[str], None]):
        self.alert_cb = alert_cb
        self.arp_table: Dict[str, str] = load_arp_cache()
        self.history: Set[str] = set()
        self.expired_cert_history: Set[str] = set()
        self.selfsigned_cert_history: Set[str] = set()

        # Tracking structures
        self.icmp_tracking: Dict[str, deque] = {}
        self.syn_tracking: Dict[str, deque] = {}
        self.scan_tracking: Dict[str, deque] = {}                    # src -> deque of (timestamp, dport)
        self.incremental_tracking: Dict[Tuple[str, str], Dict[str, Any]] = {}

        # Configuration
        self.arp_auditor_enabled = True
        self.port_scan_enabled: bool = True
        self.syn_auditor_enabled = True
        self.icmp_auditor_enabled = True

        # Port‑scan tuning – the defaults are now low enough to catch a normal
        # nmap “‑T4” sweep out‑of‑the‑box.  Users can still override them via the
        # CLI flag ``--scan-threshold`` which maps to ``port_scan_unique_threshold``.
        self.port_scan_unique_threshold: int = 12      # unique ports in window → “excessive”
        self.port_scan_sequential_threshold: int = 8   # consecutive ports → “sequential”
        self.port_scan_window: float = 10.0            # seconds

    def audit_packet(self, raw_pkt: bytes) -> None:
        """Main entry point for packet auditing."""
        try:
            eth = dpkt.ethernet.Ethernet(raw_pkt)

            # ARP Spoofing Detection
            if isinstance(eth.data, dpkt.arp.ARP):
                if not self.arp_auditor_enabled:
                    return
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

            # IP‑based traffic
            elif isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
                ip = eth.data
                src_ip = ip6_to_str(ip.src) if isinstance(ip, dpkt.ip6.IP6) else ip_to_str(ip.src)

                if isinstance(ip.data, (dpkt.tcp.TCP, dpkt.udp.UDP)):
                    transport = ip.data
                    proto = "TCP" if isinstance(transport, dpkt.tcp.TCP) else "UDP"

                    # ==== PORT‑SCAN ==== (run for *any* transport)
                    if self.port_scan_enabled:
                        self._audit_port_scan(src_ip, transport.dport,
                                              "TCP" if isinstance(transport, dpkt.tcp.TCP) else "UDP")

                    # ==== TCP SYN FLOOD ====
                    if isinstance(transport, dpkt.tcp.TCP) and self.syn_auditor_enabled:
                        if (transport.flags & dpkt.tcp.TH_SYN) and not (transport.flags & dpkt.tcp.TH_ACK):
                            self._audit_flood(src_ip, self.syn_tracking, "TCP SYN FLOOD", 50)

                # ICMP Flood
                elif (isinstance(ip.data, dpkt.icmp.ICMP) or
                      (hasattr(dpkt, 'icmp6') and isinstance(ip.data, dpkt.icmp6.ICMP6))):
                    if self.icmp_auditor_enabled:
                        self._audit_flood(src_ip, self.icmp_tracking, "ICMP FLOOD", 40)

        except Exception as e:
            logger.debug("audit_packet error: %s", e)

    def _audit_port_scan(self, src: str, dport: int, proto: str) -> None:
        """Improved detection for both random/excessive and sequential port scanning."""
        if not self.port_scan_enabled:
            return

        now = time.time()

        # === 1. Unique Ports (Best for "excessive" / random scans like Nmap -T4) ===
        if src not in self.scan_tracking:
            self.scan_tracking[src] = deque(maxlen=64)  # bound memory

        track = self.scan_tracking[src]
        track.append((now, dport))

        # Prune old entries
        while track and now - track[0][0] > self.port_scan_window:
            track.popleft()

        unique_ports = {p[1] for p in track}
        if len(unique_ports) >= self.port_scan_unique_threshold:
            msg = (f"PORT SCAN: {src} touched {len(unique_ports)} unique {proto} ports "
                   f"in last {self.port_scan_window}s")
            if msg not in self.history:
                self.history.add(msg)
                self.alert_cb(msg)

        # === 2. Sequential / Incremental Scan Detection ===
        key = (src, proto)
        if key not in self.incremental_tracking:
            self.incremental_tracking[key] = {'last': dport, 'streak': 1, 'time': now}
        else:
            state = self.incremental_tracking[key]
            time_gap = now - state['time']
            port_gap = abs(dport - state['last'])

            if time_gap > 8.0 or port_gap > 5:  # Reset on large gaps
                if state['streak'] >= self.port_scan_sequential_threshold:
                    msg = f"SEQ SCAN: {src} finished {proto} sequence of {state['streak']} ports"
                    if msg not in self.history:
                        self.history.add(msg)
                        self.alert_cb(msg)
                state['streak'] = 1
            elif port_gap >= 1:
                state['streak'] += 1

                if state['streak'] >= self.port_scan_sequential_threshold:
                    msg = f"SEQ SCAN DETECTED: {src} scanning {state['streak']} consecutive {proto} ports"
                    if msg not in self.history:
                        self.history.add(msg)
                        self.alert_cb(msg)

            state['last'] = dport
            state['time'] = now

    def _audit_flood(self, src: str, tracking_dict: Dict[str, deque], label: str, threshold: int) -> None:
        """Generic flood detection using sliding window."""
        now = time.time()
        if src not in tracking_dict:
            tracking_dict[src] = deque()

        track = tracking_dict[src]
        track.append(now)

        # Prune old entries
        while track and now - track[0] > 5.0:
            track.popleft()

        if len(track) > threshold:
            msg = f"{label}: Potential attack from {src} ({len(track)} events in 5s)"
            if msg not in self.history:
                self.history.add(msg)
                self.alert_cb(msg)

    def audit_tls(self, summary: Dict[str, Any]) -> None:
        """Surface alerts for expired / self‑signed certs (unchanged)."""
        tls_info = summary.get('tls_info') or {}
        sni = tls_info.get('sni') or summary.get('dst', '')
        for cert in tls_info.get('certs', []):
            subj = cert.get('subject', 'Unknown')
            key = f"{sni}|{subj}"
            if cert.get('is_expired') and key not in self.expired_cert_history:
                self.expired_cert_history.add(key)
                self.alert_cb(f"CERT EXPIRED: {sni} ({subj})")
            if cert.get('is_self_signed') and key not in self.selfsigned_cert_history:
                self.selfsigned_cert_history.add(key)
                self.alert_cb(f"SELF‑SIGNED CERT: {sni} ({subj})")

    def active_probe(self, target_ip: str, interface: str) -> None:
        """Send ARP probe (unchanged)."""
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
                self.alert_cb(f"[!] Probe failed: {e} (install scapy for fallback)")


# ==============================================================================
# CORE APPLICATION
# ==============================================================================

class VimSharkApp:
    """Top‑level TUI application: owns the capture thread, packet store,
    urwid widget tree, and input dispatch."""

    def __init__(self, interface: str = "eth0", read_pcap: Optional[str] = None,
                 write_pcap: Optional[str] = None, max_packets: int = 5000,
                 batch_size: int = 100, max_rate: float = 0.0,
                 max_display: int = 500, theme: str = "btop_classic", scan_threshold: int = 12):
        self.interface = interface
        self.read_pcap = read_pcap
        self.write_pcap = write_pcap
        self.max_packets = max_packets
        self.batch_size = batch_size
        self.max_rate = max_rate
        self.max_display = max_display

        self.telemetry = TrafficTelemetry()
        self.dissector = FastDissector()
        self.pkt_queue: "queue.Queue[int]" = queue.Queue()
        self.alert_queue: "queue.Queue[str]" = queue.Queue()
        self.auditor = ThreatAuditor(self.queue_alert)
        self.auditor.port_scan_unique_threshold = scan_threshold
        self.reassembler = IPReassembler()
        self.flow_tracker = FlowTracker()
        self.store = PacketStore(max_packets=max_packets)

        self.is_running = True
        self.paused = False
        self.current_theme = theme if theme in THEMES else "btop_classic"
        self.current_pkt_idx: Optional[int] = None
        self.hex_search_query = ""
        self.display_filter = ""
        self.filter_fn: Callable[[Dict[str, Any]], bool] = compile_filter("")
        self._capture_thread: Optional[threading.Thread] = None
        self.loop: Optional[urwid.MainLoop] = None

        self.setup_ui()

    # ------------------------------------------------------------------ UI
    def setup_ui(self) -> None:
        self._theme_attrs = {entry[0] for entry in THEMES[self.current_theme]}

        src = self.read_pcap or self.interface
        self.header = urwid.Text(
            f" \U0001F988 vimShark v{__version__} | {src} | Theme: {self.current_theme} | "
            f"Buffer: 0/{self.max_packets}"
        )
        self.header_attr = urwid.AttrMap(self.header, 'header')

        self.filter_edit = urwid.Edit(" Filter: ")
        urwid.connect_signal(self.filter_edit, 'change', self.on_filter_change)
        self.filter_attr = urwid.AttrMap(self.filter_edit, 'bg', 'text_focus')

        self.walker = urwid.SimpleFocusListWalker([])
        self.listbox = urwid.ListBox(self.walker)
        self.left_top = urwid.LineBox(urwid.Pile([
            ('pack', self.filter_attr),
            ('weight', 1, self.listbox),
        ]), title="Traffic Stream")

        self.tel_pkt = urwid.Text("Throughput: 0 p/s")
        self.tel_byte = urwid.Text("Bandwidth:  0 B/s")
        self.tel_total = urwid.Text("Total: 0 pkts / 0B")
        self.left_bottom = urwid.LineBox(
            urwid.Filler(urwid.Pile([self.tel_pkt, self.tel_byte, self.tel_total])),
            title="Telemetry"
        )
        self.left_pane = urwid.Pile([('weight', 4, self.left_top), ('weight', 1, self.left_bottom)])

        self.det_walker = urwid.SimpleFocusListWalker([urwid.Text("Select a packet...")])
        self.hex_walker = urwid.SimpleFocusListWalker([urwid.Text("")])
        self.alrt_walker = urwid.SimpleFocusListWalker([])

        self.right_pane = urwid.Pile([
            ('weight', 3, urwid.LineBox(urwid.ListBox(self.det_walker), title="Dissection")),
            ('weight', 2, urwid.LineBox(urwid.ListBox(self.hex_walker), title="Hex Dump")),
            ('weight', 1, urwid.LineBox(urwid.ListBox(self.alrt_walker), title="Security")),
        ])

        self.body = urwid.Columns([('weight', 3, self.left_pane), ('weight', 2, self.right_pane)], dividechars=1)
        self.footer = urwid.Text(
            " [Q]uit [T]heme [P]ause [F]ollow [S]earch Hex [E]xport [V]alidate "
            " [C]lear [L]Flows [A]uditor [/]Filter"
        )
        self.root = urwid.Frame(
            urwid.AttrMap(self.body, 'bg'),
            header=self.header_attr,
            footer=urwid.AttrMap(self.footer, 'footer'),
        )

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

        # Marker column: combine credential + TLS/JA3 indicators
        markers = []
        if summary.get('creds'):
            markers.append('!')
        tls_info = summary.get('tls_info') or {}
        if tls_info.get('alert'):
            markers.append('⚠')
        if tls_info.get('ja3') and tls_info['ja3'] != "N/A":
            markers.append('J')
        if tls_info.get('certs'):
            if any(c.get('is_expired') or c.get('is_self_signed') for c in tls_info['certs']):
                markers.append('X')
            else:
                markers.append('C')
        marker = "".join(markers).ljust(2)[:2] if markers else "  "

        line = (
            f"#{idx:<5}{marker}| {summary['src']:<22} -> {summary['dst']:<22} | "
            f"{summary['proto']:<7} | {summ_text}"
        )
        btn = urwid.Button(line)
        btn._pkt_idx = idx  # lightweight int reference only
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

        details: List[urwid.Widget] = [
            urwid.AttrMap(urwid.Text(f"### Packet #{idx} Dissection ###"), 'header'),
            urwid.Text(f"Length: {info.get('len', len(raw))} bytes"),
            urwid.Text(""),
        ]

        # Core protocol layers
        for layer_name, fields in info.get('layers', []):
            details.append(urwid.AttrMap(urwid.Text(f"-- {layer_name} --"), 'border'))
            for k, v in fields.items():
                if k == 'data' or k.startswith('_') or callable(v):
                    continue
                sval = FastDissector._safe_str(v, 90)
                details.append(urwid.Text(f"  {k:<18}: {sval}"))

        # TLS / SSL section
        tls_info = info.get('tls_info', {})
        if tls_info and tls_info.get('handshake_type') != "Unknown":
            details.append(urwid.Text(""))
            details.append(urwid.AttrMap(urwid.Text("=== TLS / SSL ==="), 'pkt_tls'))
            details.append(urwid.Text(f"  Message Type : {tls_info.get('handshake_type')}"))

            if tls_info.get('version_name'):
                ver_text = tls_info['version_name']
                if tls_info.get('tls13') and "1.3" not in ver_text:
                    ver_text += " (negotiating TLS 1.3)"
                details.append(urwid.Text(f"  Version      : {ver_text}"))

            if tls_info.get('cipher'):
                cipher_id = tls_info['cipher']
                name = FastDissector._CIPHER_SUITES.get(cipher_id, "UNKNOWN")
                details.append(urwid.Text(f"  Cipher Suite : 0x{cipher_id:04x} ({name})"))

            if tls_info.get('sni'):
                details.append(urwid.Text(f"  SNI          : {tls_info['sni']}"))

            if tls_info.get('alpn'):
                details.append(urwid.Text(f"  ALPN         : {', '.join(tls_info['alpn'])}"))

            if tls_info.get('alert'):
                details.append(urwid.AttrMap(
                    urwid.Text(f"  TLS Alert    : {tls_info['alert']}"), 'warn'))

            # JA3 (client fingerprint)
            ja3 = tls_info.get('ja3')
            if ja3 and ja3 != "N/A":
                details.append(urwid.AttrMap(urwid.Text(f"  JA3          : {ja3}"), 'ja3'))
                ja3i = tls_info.get('ja3_info', {})
                if ja3i.get('ciphers'):
                    details.append(urwid.Text(f"    Ciphers    : {len(ja3i['ciphers'])} offered"))
                if ja3i.get('curves'):
                    details.append(urwid.Text(f"    Curves     : {'-'.join(map(str, ja3i['curves']))}"))
                if ja3i.get('supported_versions'):
                    vnames = [_TLS_VERSION_NAMES.get(v, f"0x{v:04x}") for v in ja3i['supported_versions']]
                    details.append(urwid.Text(f"    Offers     : {', '.join(vnames)}"))

            # JA3S (server fingerprint)
            ja3s = tls_info.get('ja3s')
            if ja3s and ja3s != "N/A":
                details.append(urwid.AttrMap(urwid.Text(f"  JA3S         : {ja3s}"), 'ja3'))

            if tls_info.get('ocsp_stapled'):
                details.append(urwid.AttrMap(urwid.Text("  OCSP Stapling: Present"), 'good'))

            # Certificates
            certs = tls_info.get('certs', [])
            if certs:
                details.append(urwid.Text(""))
                details.append(urwid.AttrMap(
                    urwid.Text(f"=== Certificates ({len(certs)}) ==="), 'pkt_tls'))

                for i, cert in enumerate(certs):
                    bad = cert.get('is_expired') or cert.get('is_self_signed') or cert.get('is_not_yet_valid')
                    header_color = 'warn' if bad else 'pkt_tls'
                    details.append(urwid.AttrMap(urwid.Text(f"  Cert #{i + 1}:"), header_color))

                    details.append(urwid.Text(f"    Subject   : {cert.get('subject', 'Unknown')}"))
                    details.append(urwid.Text(f"    Issuer    : {cert.get('issuer', 'Unknown')}"))
                    details.append(urwid.Text(
                        f"    Valid     : {fmt_ts(cert.get('not_before'))} -> {fmt_ts(cert.get('not_after'))}"
                    ))

                    days = cert.get('days_remaining')
                    if days is not None and not cert.get('is_expired'):
                        warn_soon = days <= 14
                        details.append(urwid.AttrMap(
                            urwid.Text(f"    Expires in: {days} day(s)"),
                            'warn' if warn_soon else 'dim'
                        ))

                    if cert.get('is_expired'):
                        details.append(urwid.AttrMap(urwid.Text("    [!] CERTIFICATE EXPIRED"), 'warn'))
                    if cert.get('is_not_yet_valid'):
                        details.append(urwid.AttrMap(urwid.Text("    [!] CERTIFICATE NOT YET VALID"), 'warn'))
                    if cert.get('is_self_signed'):
                        details.append(urwid.AttrMap(urwid.Text("    [!] Self‑Signed Certificate"), 'warn'))

                    if cert.get('pubkey_algorithm'):
                        details.append(urwid.Text(f"    Public Key: {cert['pubkey_algorithm']}"))
                    if cert.get('signature_algorithm'):
                        details.append(urwid.Text(f"    Signature : {cert['signature_algorithm']}"))
                    if cert.get('serial'):
                        details.append(urwid.Text(f"    Serial    : {cert['serial']}"))

                    if cert.get('san'):
                        san_preview = ', '.join(cert['san'][:5])
                        if len(cert['san']) > 5:
                            san_preview += " ..."
                        details.append(urwid.Text(f"    SAN       : {san_preview}"))

                    fp256 = cert.get('fingerprint_sha256')
                    if fp256:
                        details.append(urwid.Text(f"    SHA256    : {fp256}"))
                    fp1 = cert.get('fingerprint_sha1')
                    if fp1:
                        details.append(urwid.Text(f"    SHA1      : {fp1}"))

                    if cert.get('ocsp_responders'):
                        details.append(urwid.Text(f"    OCSP      : {cert['ocsp_responders'][0]}"))
                    if cert.get('crl_distribution_points'):
                        details.append(urwid.Text(f"    CRL       : {cert['crl_distribution_points'][0]}"))

        # Credential warnings
        if info.get('creds'):
            details.append(urwid.Text(""))
            details.append(urwid.AttrMap(urwid.Text("!! POTENTIAL CREDENTIAL EXPOSURE !!"), 'warn'))
            for c in info['creds']:
                details.append(urwid.Text(f"   - {c}"))

        self.det_walker[:] = details
        self.update_hex_view()

    def update_hex_view(self) -> None:
        if self.current_pkt_idx is None:
            self.hex_walker[:] = [urwid.Text("")]
            return
        item = self.store.get(self.current_pkt_idx)
        if not item:
            return
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
                    parts.extend([line[last_end:start], ('selected', line[start:start + len(query)])])
                    last_end = start + len(query)
                    start = lower_line.find(query, last_end)
                parts.append(line[last_end:])
                new_hex_rows.append(urwid.Text(parts))
            else:
                new_hex_rows.append(urwid.Text(line))
        self.hex_walker[:] = new_hex_rows

    # --------------------------------------------------------------- capture
    def capture_loop(self) -> None:
        """Background thread: capture, dissect, store, enqueue index only.
        Never touches urwid widgets directly."""
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

                self._process_packet(data, header)

            except pcapy.PcapError:
                continue
            except Exception as e:
                logger.exception("capture loop error")
                self.queue_alert(f"Capture error: {e}")
                time.sleep(0.1)

    def _process_packet(self, data: bytes, header: Any) -> None:
        """Dissect a single raw frame, store it, and queue follow‑up work
        (telemetry, flow tracking, security audits, fragment reassembly)."""
        summary = self.dissector.dissect(data)
        ts_sec, ts_usec = header.getts()
        ts = ts_sec + ts_usec / 1_000_000.0

        idx = self.store.add(data, summary, ts)
        self.pkt_queue.put(idx)

        self.telemetry.accumulate(len(data))
        self.flow_tracker.update(summary, ts)
        self.auditor.audit_packet(data)
        if summary.get('proto') == 'TLS':
            self.auditor.audit_tls(summary)

        # IPv4 fragmentation reassembly
        try:
            eth = dpkt.ethernet.Ethernet(data)
            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data
                if ip.off & (dpkt.ip.IP_MF | dpkt.ip.IP_OFFMASK):
                    full_payload = self.reassembler.process(ip)
                    if full_payload:
                        ip.data = full_payload
                        ip.off = 0
                        ip.len = len(ip)
                        eth.data = ip
                        res_raw = bytes(eth)
                        res_summary = self.dissector.dissect(res_raw)
                        res_summary['summary'] = "[REASSEMBLED] " + res_summary['summary']
                        res_idx = self.store.add(res_raw, res_summary, ts)
                        self.pkt_queue.put(res_idx)
                        if res_summary.get('proto') == 'TLS':
                            self.auditor.audit_tls(res_summary)
        except Exception as e:
            logger.debug("reassembly handling error: %s", e)

    # ----------------------------------------------------------------- tick
    def ui_update_tick(self, loop: urwid.MainLoop, _user_data: Any) -> None:
        """Main‑thread heartbeat: drains queues in batches, updates telemetry."""
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
        if self.alrt_walker:
            self.alrt_walker.set_focus(len(self.alrt_walker) - 1)

        pr, br = self.telemetry.tick()
        self.tel_pkt.set_text(f"Throughput: {self.telemetry.format_unit(pr)} p/s  {self.telemetry.get_sparkline('p')}")
        self.tel_byte.set_text(f"Bandwidth:  {self.telemetry.format_unit(br, True)}/s  {self.telemetry.get_sparkline('b')}")
        self.tel_total.set_text(
            f"Total: {self.telemetry.format_unit(self.telemetry.total_packets)} pkts / "
            f"{self.telemetry.format_unit(self.telemetry.total_bytes, True)}"
        )

        status = "PAUSED" if self.paused else "LIVE"
        mode = "READ" if self.read_pcap else "CAPTURE"
        src = self.read_pcap or self.interface
        self.header.set_text(
            f" \U0001F988 vimShark v{__version__} | {src} | {mode} [{status}] | "
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
            self.flow_tracker.clear()
            self.walker[:] = []
            self.update_hex_view()
            # Reset auditor state on manual clear
            self.auditor.history.clear()
            self.auditor.expired_cert_history.clear()
            self.auditor.selfsigned_cert_history.clear()
            self.auditor.icmp_tracking.clear()
            self.auditor.syn_tracking.clear()
            self.auditor.scan_tracking.clear()
            self.auditor.incremental_tracking.clear()
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
        elif key in ('l', 'L'):
            self.show_flows_modal()
        elif key in ('a', 'A'):
            self.show_auditor_modal()

    def cycle_theme(self) -> None:
        names = list(THEMES.keys())
        cur = names.index(self.current_theme)
        self.current_theme = names[(cur + 1) % len(names)]
        self._theme_attrs = {entry[0] for entry in THEMES[self.current_theme]}
        if self.loop is not None:
            self.loop.screen.register_palette(THEMES[self.current_theme])
            self.loop.screen.clear()
        self.refresh_display()

    # --------------------------------------------------------------------- AUDITOR UI
    def _auditor_status(self) -> str:
        """Return a short status string used in the footer."""
        parts = []
        if self.auditor.arp_auditor_enabled:
            parts.append('ARP')
        if self.auditor.port_scan_enabled:
            parts.append('PORT‑SCAN')
        if self.auditor.syn_auditor_enabled:
            parts.append('SYN')
        if self.auditor.icmp_auditor_enabled:
            parts.append('ICMP')
        return ', '.join(parts) or 'none'

    def _update_footer(self) -> None:
        """Re‑build the footer text so the toggle status is always visible."""
        base = " [Q]uit [T]heme [P]ause [F]ollow [S]earch Hex [E]xport [V]alidate " \
               "[C]lear [L]Flows [A]uditor [/]Filter"
        status = f"  Enabled: {self._auditor_status()}"
        self.footer.set_text(base + status)

    def show_auditor_modal(self) -> None:
        """Overlay with check‑boxes for each audit component."""
        cb_arp   = urwid.CheckBox('ARP Spoof Detector', state=self.auditor.arp_auditor_enabled)
        cb_port  = urwid.CheckBox('Port‑Scan Detector', state=self.auditor.port_scan_enabled)
        cb_syn   = urwid.CheckBox('TCP SYN‑Flood Detector', state=self.auditor.syn_auditor_enabled)
        cb_icmp  = urwid.CheckBox('ICMP Flood Detector', state=self.auditor.icmp_auditor_enabled)
        ok_btn   = urwid.Button('OK')
        cancel   = urwid.Button('Cancel')

        def apply(_b):
            self.auditor.arp_auditor_enabled   = cb_arp.get_state()
            self.auditor.port_scan_enabled      = cb_port.get_state()
            self.auditor.syn_auditor_enabled    = cb_syn.get_state()
            self.auditor.icmp_auditor_enabled   = cb_icmp.get_state()
            self._update_footer()
            self._close_overlay()

        urwid.connect_signal(ok_btn,    'click', apply)
        urwid.connect_signal(cancel,    'click', self._close_overlay)

        pile = urwid.Pile([
            urwid.Text('--- Security Auditor Settings ---', align='center'),
            urwid.Divider(),
            cb_arp, cb_port, cb_syn, cb_icmp,
            urwid.Divider(),
            urwid.Columns([ok_btn, cancel])
        ])
        overlay = urwid.Overlay(
            urwid.LineBox(urwid.Filler(pile), title='Auditor Settings'),
            self.root.body, 'center', 48, 'middle', 16
        )
        self.root.body = overlay

    def _close_overlay(self, *_args) -> None:
        self.root.body = urwid.AttrMap(self.body, 'bg')

    # ------------------------------------------------------------- modals (export / hex / validation / flows)
    def show_validation_modal(self) -> None:
        edit = urwid.Edit("Target IP: ", "192.168.1.1")
        cb_arp = urwid.CheckBox("Passive ARP Validator", state=self.auditor.arp_auditor_enabled)
        cb_scan = urwid.CheckBox("Port Scan Detection", state=self.auditor.port_scan_enabled)
        btn = urwid.Button("Dispatch Probe")
        cancel = urwid.Button("Cancel")

        def go(_b):
            self.auditor.arp_auditor_enabled = cb_arp.get_state()
            self.auditor.port_scan_enabled = cb_scan.get_state()
            self.auditor.active_probe(edit.get_edit_text(), self.interface)
            self._close_overlay()

        urwid.connect_signal(btn, 'click', go)
        urwid.connect_signal(cancel, 'click', self._close_overlay)

        pile = urwid.Pile([
            urwid.Text("--- Security Configuration ---"),
            urwid.Divider(),
            cb_arp,
            cb_scan,
            urwid.Divider(),
            urwid.Text("--- Active ARP Probe ---"),
            edit,
            urwid.Columns([btn, cancel])
        ])

        overlay = urwid.Overlay(
            urwid.LineBox(urwid.Filler(pile), title="Security Validator"),
            self.root.body, 'center', 48, 'middle', 13
        )
        self.root.body = overlay

    def show_hex_search_modal(self) -> None:
        edit = urwid.Edit("Search Hex/ASCII: ", self.hex_search_query)
        btn, clear, cancel = urwid.Button("Search"), urwid.Button("Clear"), urwid.Button("Cancel")

        def do_search(_b):
            self.hex_search_query = edit.get_edit_text()
            self.update_hex_view()
            self._close_overlay()

        def do_clear(_b):
            self.hex_search_query = ""
            self.update_hex_view()
            self._close_overlay()

        urwid.connect_signal(btn, 'click', do_search)
        urwid.connect_signal(clear, 'click', do_clear)
        urwid.connect_signal(cancel, 'click', self._close_overlay)

        overlay = urwid.Overlay(
            urwid.LineBox(
                urwid.Filler(urwid.Pile([edit, urwid.Divider(), urwid.Columns([btn, clear, cancel])])),
                title="Hex Dump Search"
            ),
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
            self._close_overlay()

        urwid.connect_signal(btn, 'click', do_export)
        urwid.connect_signal(cancel, 'click', self._close_overlay)

        overlay = urwid.Overlay(
            urwid.LineBox(urwid.Filler(urwid.Pile([edit, urwid.Divider(), btn, cancel])), title="Export Filtered Traffic"),
            self.root.body, 'center', 45, 'middle', 9
        )
        self.root.body = overlay

    def show_flows_modal(self) -> None:
        """Display the top flows by byte count, with JA3 hints where available."""
        rows: List[urwid.Widget] = [
            urwid.AttrMap(urwid.Text("--- Top Flows (by bytes, press q to close) ---"), 'header'),
            urwid.Text(""),
        ]
        for flow in self.flow_tracker.top_flows(20):
            a, b = flow['endpoints']
            size = TrafficTelemetry.format_unit(flow['bytes'], True)
            rows.append(urwid.Text(
                f"{a:<24} <-> {b:<24} | {flow['proto']:<5} | "
                f"{flow['packets']:>6} pkts | {size:>8}"
            ))
        if len(rows) == 2:
            rows.append(urwid.Text("(no flows recorded yet)"))

        close_btn = urwid.Button("Close")
        parent = self.root.body
        urwid.connect_signal(close_btn, 'click', lambda _b: setattr(self.root, 'body', parent))
        rows.append(urwid.Text(""))
        rows.append(close_btn)

        self.root.body = urwid.Overlay(
            urwid.LineBox(urwid.ListBox(urwid.SimpleListWalker(rows)), title="Flow Table"),
            parent, 'center', ('relative', 80), 'middle', ('relative', 80)
        )

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
                proto_class: type = dpkt.tcp.TCP
                proto_label = "TCP"
            elif isinstance(ip_pkt.data, dpkt.udp.UDP):
                proto_class = dpkt.udp.UDP
                proto_label = "UDP"
            else:
                return

            transport = ip_pkt.data
            addr_set = {(ip_pkt.src, transport.sport), (ip_pkt.dst, transport.dport)}
            orig_src = (ip_pkt.src, transport.sport)
            is_v6 = isinstance(ip_pkt, dpkt.ip6.IP6)
            addr_to_str = ip6_to_str if is_v6 else ip_to_str

            src_str = addr_to_str(ip_pkt.src)
            dst_str = addr_to_str(ip_pkt.dst)

            stream_rows: List[urwid.Widget] = [
                urwid.AttrMap(urwid.Text(
                    f"--- {proto_label} Stream {src_str}:{transport.sport} <-> "
                    f"{dst_str}:{transport.dport} (press q to close) ---"
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
                if not p_data.data:
                    continue

                payload = p_data.data
                if not isinstance(payload, bytes):
                    try:
                        payload = bytes(payload)
                    except Exception:
                        continue

                txt = "".join(chr(b) if 32 <= b <= 126 or b in (10, 13) else "." for b in payload)
                direction = '->' if (p_ip.src, p_data.sport) == orig_src else '<-'
                color = 'pkt_tcp' if direction == '->' else 'pkt_udp'

                markup: List[Any] = [f"[{direction}] "]
                highlighted = self._get_highlighted_markup(txt, self.hex_search_query)
                if isinstance(highlighted, list):
                    markup.extend(highlighted)
                else:
                    markup.append(highlighted)

                stream_rows.append(urwid.AttrMap(urwid.Text(markup), color))

            close_btn = urwid.Button("Close")
            parent = self.root.body
            urwid.connect_signal(close_btn, 'click', lambda _b: setattr(self.root, 'body', parent))
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

def main() -> None:
    parser = argparse.ArgumentParser(description=f"vimShark v{__version__}")
    parser.add_argument("-i", "--interface", default="eth0", help="Capture interface")
    parser.add_argument("-r", "--read", help="Read from a PCAP file instead of live capture")
    parser.add_argument("-o", "--output", help="Write captured packets to a PCAP file")
    parser.add_argument("-b", "--buffer", type=int, default=5000,
                        help="Packet store capacity (ring buffer size)")
    parser.add_argument("--scan-threshold", type=int, default=12,
                        help="Threshold for scan detection.")
    parser.add_argument("--batch-size", type=int, default=100,
                        help="Max packets drained from queue per UI tick")
    parser.add_argument("--max-rate", type=float, default=0.0,
                        help="Throttle: max packets/sec to process (0 = unlimited)")
    parser.add_argument("--max-display", type=int, default=500,
                        help="Max rows kept in the visible traffic list")
    parser.add_argument("--theme", default="btop_classic",
                        choices=list(THEMES.keys()), help="Initial color theme")
    parser.add_argument("--log-level", default="WARNING",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                        help="Log verbosity (written to vimshark.log)")
    parser.add_argument("--credits",action="store_true",help="Shows credits & exits.")
    args = parser.parse_args()

    logger.setLevel(getattr(logging, args.log_level))
    
    if args.credits:
        banner = [

        ]
        lines = [
            "Developed"
        ]
        print("\n".join(lines))
        sys.exit(0)

    if not CRYPTOGRAPHY_AVAILABLE:
        logger.warning("'cryptography' not installed - certificate parsing will be limited to SHA fingerprints")

    app = VimSharkApp(
        interface=args.interface,
        read_pcap=args.read,
        write_pcap=args.output,
        max_packets=args.buffer,
        batch_size=args.batch_size,
        max_rate=args.max_rate,
        max_display=args.max_display,
        theme=args.theme,
        scan_threshold=args.scan_threshold,
    )
    app.run()


if __name__ == "__main__":
    main()
