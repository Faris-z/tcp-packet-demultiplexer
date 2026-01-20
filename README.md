# TCP/IP Packet Demultiplexer

A Python-based TCP/IP packet demultiplexer built using **Scapy**.  
This project captures live **TCP traffic** from a selected network interface, extracts the source/destination IP addresses and ports (TCP 4-tuple), and saves each packet’s **payload** into a separate text file for analysis.

Each payload is saved as a **hexadecimal string** to preserve the exact bytes captured from the network, and the generated files are stored inside an `output/` folder with filenames that include the connection details and timestamp.

This tool is useful for basic network traffic inspection, debugging TCP communication, and understanding how packet demultiplexing works in real network environments.
