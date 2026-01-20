# TCP/IP Packet Demultiplexer

A Python-based TCP/IP packet demultiplexer that captures live TCP traffic from a selected network interface, extracts useful packet information (source/destination IPs and ports), and saves the payload of each packet into separate text files for later analysis.

Each payload is stored as a **hexadecimal string** to preserve the exact byte values while remaining safe to view in any text editor.

---

## 🚀 Features
* **Live Capture**: Captures live TCP packets from a selected network interface.
* **4-Tuple Extraction**: Identifies flows using Source IP/Port and Destination IP/Port.
* **Payload Storage**: Saves each TCP payload into a separate `.txt` file inside the `output/` directory.
* **Hex Formatting**: Payloads are saved as hex strings for safe analysis.
* **Smart Filtering**: Automatically ignores non-TCP packets and TCP packets with **0-byte payloads** (pure ACK/SYN, etc.).
* **Testing**: Includes unit and integration-style tests using `unittest`.

---

## 🛠️ Requirements & Dependencies

### Software
* **Python 3.10+**
* **Npcap** (Required for packet capture on Windows)
* **IDE/Editor** (VS Code recommended)

### Python Libraries
Install the required library using pip:
```bash
pip install scapy
```
> **Note for Windows Users:** Install **Npcap** with "WinPcap API compatibility" enabled so Scapy can capture packets correctly.

---

## 📂 Project Structure
```text
.
├── main.py          # Interface selection + starts packet capture
├── packetUtil.py    # Packet capture + demultiplexing + payload saving
├── tests.py         # Unit + integration-style tests
└── output/          # Generated payload files (created automatically)
