# TCP/IP Packet Demultiplexer

A TCP/IP packet demultiplexer built in Python using **Scapy**.  
It captures live TCP traffic from a selected network interface, extracts payload data, and stores each packet payload as a **hex text file** inside an `output/` folder.

Each output file is named using the format:

[timestamp]sourceip.sourceport-destip.destport.txt

---

## Features
- Captures **live TCP packets** using Scapy sniffing
- Filters only valid **IP + TCP** packets
- Extracts TCP payload (Raw data only)
- Saves payloads as **hex strings** in output files
- Ignores:
  - Non-TCP packets
  - TCP packets with **0-byte payload** (ACK-only packets)
- Includes **unit and integration tests** using `unittest`

---

## Project Structure

.
├── main.py # Interface selection + starts capture
├── packetUtil.py # Packet capture + demultiplexing + payload saving
├── tests.py # Unit tests + integration test replay
└── output/ # Generated payload hex files


---

## Requirements
- Python 3.x
- Scapy
- Packet capture driver installed:
  - **Npcap** (recommended on Windows)

Install dependencies:
```bash
pip install scapy

How To Run
1) Start the demultiplexer:
python main.py
2) Choose the interface:
The program prints available interfaces

Press ENTER to use default: Wi-Fi

Or type a different interface name

3) Stop the capture:
Press:

Ctrl + C
Output Example
Console output example:

192.168.0.10:50500 -> 162.159.135.234:443 | 46 bytes
Generated file example in output/:

2025-11-30-14-20-10-123456_192.168.0.10.50500-162.159.135.234.443.txt
File content:

Hex encoding of the TCP payload

Testing
Run all tests:

python -m unittest tests.py
Example of a single test:

python -m unittest tests.PacketUtilTests.test_tcp_packet_with_payload_creates_file_with_correct_hex
Integration test:

If ValidationRun.pcapng exists, the system replays packets through the handler and checks output.

Notes
On Windows, you may need to run the terminal/IDE as Administrator to capture packets.

Only TCP packets with payload are saved to avoid creating useless files from ACK-only packets.
