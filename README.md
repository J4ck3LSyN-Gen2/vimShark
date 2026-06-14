# 🦈 vimShark

**Author:** J4ck3LSyN  
**Version:** 0.2.0

---

<p align="center">
  <img src="docs/vsBloody.png" width="45%" />
  <img src="docs/vsE2.png" width="45%" />
  <br />
  <img src="docs/arch.png" width="45%" />
  <img src="docs/btopClassic.png" width="45%" />
</p>

---

**vimShark** is a high-performance, terminal-based network telemetry analyzer and security auditing tool. Engineered for systems administrators and security researchers, it provides a production-grade TUI (Terminal User Interface) for real-time packet dissection, flow reassembly, and passive threat detection.

Built on the high-speed **dpkt** parsing engine and **pcapy-ng** for low-latency capture, vimShark delivers deep packet insights directly in your terminal with support for 24-bit True Color themes.

## Key Features

*   **Real-Time Telemetry**: Live packet-per-second (pps) and throughput (bps) monitoring with Unicode-block sparkline visualizations.
*   **Deep Packet Dissection**: Structural decoding of Ethernet, IPv4/IPv6, ARP, TCP, UDP, ICMP, DNS, NTP, and more.
*   **Encrypted Traffic Insight**: SNI extraction, full X.509 certificate parsing, and OCSP stapling detection.
*   **IP Reassembly**: Native stateful reassembly of fragmented IPv4 traffic.
*   **Stream Reassembly**: Full-duplex TCP/UDP stream following and payload reconstruction.
*   **Hex/ASCII Search**: Interactive pattern matching and highlighting within the hex dump viewer.
*   **Security Auditing**: 
    *   **Passive ARP Spoof Detection**: Monitors MAC-to-IP binding changes against system baselines.
    *   **Active Validation**: Dispatch targeted ARP probes (via raw sockets or Scapy) to verify disputed network identities.
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
    python3 -m pip install urwid dpkt pcapy-ng
    # Optional: pip install cryptography (for cert parsing) scapy (for active probe fallback)
    # Note: Use -t . if you have environment issues with sudo/venv
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
sudo python3 vs.py -i eth0
```

### Offline Analysis
Analyze a pre-captured PCAP file:
```bash
python3 vs.py -r capture.pcap
```

### Live Export
Capture live traffic and mirror the stream to a file simultaneously:
```bash
sudo python3 vs.py -i eth0 -o output.pcap
```

## ⌨️ Interactive Keybindings

| Key | Action |
| :--- | :--- |
| `Q` / `ESC` | Quit / Close Overlay |
| `T` | Cycle UI Themes |
| `P` | Pause/Resume Live Capture |
| `/` | Focus Filter Bar |
| `S` | Search Strings Inside of Hex Dumps |
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
