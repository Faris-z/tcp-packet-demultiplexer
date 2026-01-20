from packetUtil import packetCapture
from scapy.all import conf

# interface "Wi-Fi" for default
DEFAULT_INTERFACE = "Wi-Fi"


def choose_interface():
    """
    Show available interfaces and let the user choose one by name/description.
    Returns the resolved interface name that Scapy can use, or None on failure.
    """
    print("Available interfaces:")
    iface_map = {}

    # Build a map so we accept both iface.name and iface.description
    for iface in conf.ifaces.values():
        desc = getattr(iface, "description", str(iface))
        name = getattr(iface, "name", str(iface))
        print(f" - {desc} ({name})")
        iface_map[name] = name
        iface_map[desc] = name

    print()
    print(f"Press ENTER to use the default interface: {DEFAULT_INTERFACE}")
    user_iface = input("Enter interface name or description: ").strip()

    # Use default if user just presses ENTER
    if not user_iface:
        requested = DEFAULT_INTERFACE
    else:
        requested = user_iface

    # Try to resolve requested to an actual interface name
    if requested in iface_map:
        return iface_map[requested]

    print(f"\n[!] Interface '{requested}' not found.")
    print("    Please choose one of the names/descriptions shown above.")
    return None


def main():
    print("[*] TCP Packet Demultiplexer")
    print("[*] Payloads will be stored as hex text files inside the output/ folder.\n")

    iface_name = choose_interface()
    if not iface_name:
        # Invalid choice; exit
        return

    print(f"\n[*] Using interface: {iface_name}")
    print("[*] Press Ctrl+C to stop.\n")

    packetCapture(iface_name)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] Stopped by user.")
    except Exception as e:
        print(f"[!] Fatal error in main: {e}")
