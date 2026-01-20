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

