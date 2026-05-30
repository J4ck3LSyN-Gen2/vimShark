# 🦈 vimShark

**Author:** J4ck3LSyN  
**Version:** 0.1.6  

---

<p align="center">
  <img src="docs/vsBloody.png" width="48%" />
  <img src="docs/vsE2.png" width="48%" />
</p>

---

**vimShark** is a high-performance, terminal-based network telemetry analyzer and security auditing tool. Engineered for systems administrators and security researchers, it provides a production-grade TUI (Terminal User Interface) for real-time packet dissection, flow reassembly, and passive threat detection.

Built on the robust **Scapy** engine and rendered with **Urwid**, vimShark delivers deep packet insights directly in your terminal with support for 24-bit True Color themes.

## Key Features

*   **Real-Time Telemetry**: Live packet-per-second (pps) and throughput (bps) monitoring with Unicode-block sparkline visualizations.
*   **Deep Packet Dissection**: Structural decoding of Ethernet, IPv4/IPv6, ARP, TCP, UDP, ICMP, DNS, NTP, and more.
*   **Encrypted Traffic Identification**: Native detection of TLS/SSL handshakes and HTTP traffic layers.
*   **Stream Reassembly**: Full-duplex TCP/UDP stream following and payload reconstruction.
*   **Security Auditing**: 
    *   **Passive ARP Spoof Detection**: Monitors MAC-to-IP binding changes against system baselines.
    *   **Active Validation**: Dispatch targeted ARP probes to verify disputed network identities.
    *   **Credential Leak Detection**: Passive scanning for unencrypted sensitive keywords (user, pass, secret, etc.) in raw payloads.
*   **Advanced Filtering**: Support for complex display filters using logic operators (`&&`, `||`, `==`).
*   **Persistence**: Read from and write to standard PCAP files for offline forensic analysis.
*   **Highly Customizable**: 8+ built-in color schemes including Dracula, Nord, Gruvbox, and Cyberpunk.

### Prerequisites

vimShark requires Python 3.8+ and administrative privileges to bind to raw sockets.

##  Quick Start

1. **Git the Repo**
    ```bash
    git clone https://github.com/J4ck3LSyN-Gen2/vimShark.git
    cd vimShark
    ```
2. **Open a Virtual Environment**
    ```bash
    python3 -m venv vsEnviron
    source vsEnviron/bin/activate # (.fish if your swimming...)
    ```
3. **Install Modules**
    > *Note: Depending on your OS, you may need to install `tcpdump` or `libpcap` for Scapy to interface correctly with your network hardware*
    ```bash
    python3 -m pip install --upgrade pip
    python3 -m pip install -r requirements.txt
    # Or
    python3 -m pip install scapy uwid
    # NOTE: If you find that 'scapy' is struggling, install it in your flavor.
    # pacman -S python-scapy
    # apt-get install python-scapy Or apt-get install python3-scapy
    ```
4. **Run vimShark**
    ```bash
    # Requires ROOT
    sudo python3 vs.py -i wlan0 # <wlan0> being the desired interface.
    sudo python3 vs.py -i wlan0 -o cap_wlan0.pcap # Captures all packets during session to 'cap_wlan0.pcap'.
    sudo python3 vs.py -r cap_wlan0.pcap # Read traffic from 'cap_wlan0.pcap'.
    ```
5. **Deactivate**
    ```bash
    deactivate
    ```

## 🛠 Usage

### Basic Sniffing
Capture traffic on the default interface (usually `eth0` or `wlan0`):
```bash
sudo python3 vs004.py -i eth0
```

### Offline Analysis
Analyze a pre-captured PCAP file:
```bash
python3 vs004.py -r capture.pcap
```

### Live Export
Capture live traffic and mirror the stream to a file simultaneously:
```bash
sudo python3 vs004.py -i eth0 -o output.pcap
```

## ⌨️ Interactive Keybindings

| Key | Action |
| :--- | :--- |
| `Q` / `ESC` | Quit / Close Overlay |
| `T` | Cycle UI Themes |
| `P` | Pause/Resume Live Capture |
| `/` | Focus Filter Bar |
| `F` | Follow TCP/UDP Stream (on selected packet) |
| `V` | Trigger Active ARP Validation Probe |
| `C` | Clear Packet Buffer |
| `Enter` | Inspect Selected Packet |
| `Arrows` | Navigate Packet List / Hex Dumps |

## '/' Display Filters

vimShark supports a powerful filtering syntax to isolate specific traffic. You can combine fields using `&&` (AND) and `||` (OR).

**Example Queries:**
*   `type == tcp && ip.src == 192.168.1.5`
*   `type == dns || type == ntp`
*   `in_data == 414141` (Search hex pattern in raw payload)

## 'T' Supported Themes

Change the aesthetic of your analysis environment on the fly:
*   **btop_classic**: High-contrast professional blue.
*   **Dracula**: The classic dark mode favorite.
*   **Nord**: Arctic-inspired clean aesthetic.
*   **Gruvbox**: Retro "groove" dark theme.
*   **Cyberpunk**: High-saturation neon visuals.
*   **Solarized Dark**: Precision-calibrated color palette.

## Security Disclaimer

This tool is intended for authorized network monitoring and security auditing only. Using vimShark for unauthorized interception of traffic on networks you do not own or have explicit permission to audit is illegal and unethical. The authors assume no liability for misuse of this software.

## License

Distributed under the MIT License. See `LICENSE` for more information.

---
