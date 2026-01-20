import os
from datetime import datetime
from scapy.all import IP, TCP, Raw, sniff

# Make sure the output folder exists
OUTPUT_DIR = "output"
os.makedirs(OUTPUT_DIR, exist_ok=True)


def packet_handler(pkt):
    """
    Handle each captured TCP packet.
    Extract and print IPs, ports, and payload size, and
    store the TCP payload (if any) as hex into a file.
    """

    # Process only IP/TCP packets
    if IP not in pkt or TCP not in pkt:
        return

    ip_layer = pkt[IP]
    tcp_layer = pkt[TCP]

    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    src_port = tcp_layer.sport
    dst_port = tcp_layer.dport

    # Extract payload bytes (may be empty)
    payload_bytes = b""
    if Raw in pkt and pkt[Raw].load is not None:
        payload_bytes = pkt[Raw].load

    payload_len = len(payload_bytes)

    # Log to console
    print(f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} | {payload_len} bytes")

    # Nothing to store for 0-byte payloads (pure ACKs, etc.)
    if not payload_bytes:
        return

    # Timestamp for unique file name – try to use packet time, fall back to now()
    try:
        ts = datetime.fromtimestamp(float(pkt.time))
    except Exception:
        ts = datetime.now()
    ts_str = ts.strftime("%Y-%m-%d-%H-%M-%S-%f")

    # Make IPs filesystem-safe (handle IPv6 with colons)
    safe_src_ip = src_ip.replace(":", "_")
    safe_dst_ip = dst_ip.replace(":", "_")

    # [timestamp]srcip.srcport-dstip.dstport.txt
    filename = f"{ts_str}_{safe_src_ip}.{src_port}-{safe_dst_ip}.{dst_port}.txt"
    file_path = os.path.join(OUTPUT_DIR, filename)

    # Convert payload to hex and write to file with error handling
    hex_data = payload_bytes.hex()
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(hex_data)
    except OSError as e:
        print(f"[!] Failed to write payload to {file_path}: {e}")


def packetCapture(interface: str):
    """
    Start capturing TCP packets on the given interface.
    For each captured packet, call packet_handler(pkt).

    :param interface: Name of the network interface (e.g., 'Wi-Fi')
    """
    print(f"[*] Starting TCP capture on interface: {interface}")
    print("[*] Press Ctrl+C to stop.")

    try:
        sniff(
            iface=interface,   # which interface to listen on
            filter="tcp",      # capture only TCP packets
            prn=packet_handler,
            store=False        # do not store packets in memory
        )
        # Safety mesures in case sniff exits 
    except PermissionError:
        print("[!] Permission denied while opening the interface.")
        print("    On Windows, try running the terminal / IDE as Administrator.")
    except ValueError as e:
        print(f"[!] Invalid interface '{interface}': {e}")
    except OSError as e:
        print(f"[!] OS-level error while capturing on {interface}: {e}")
    except KeyboardInterrupt:
        print("\n[*] Capture stopped by user.")
    except Exception as e:
        print(f"[!] Unexpected error in packetCapture: {e}")
