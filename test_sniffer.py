from scapy.all import *

# --- VERY IMPORTANT ---
# Replace "YOUR_INTERFACE_NAME" with the actual name you found.
# Examples: "Wi-Fi" (Windows), "en0" (macOS), "wlan0" (Linux)
INTERFACE_TO_TEST = "Ethernet" 

def simple_print(packet):
    print("Success! A packet was captured.")

print(f"--- Starting Diagnostic Sniffer on interface: {INTERFACE_TO_TEST} ---")
print("--- Generating simple network traffic now (e.g., open a webpage). ---")
print("--- If you see no 'Success!' messages, the problem is the interface or a firewall. ---")

try:
    # We will only capture 5 packets for this test, then stop.
    sniff(prn=simple_print, iface=INTERFACE_TO_TEST, store=0, count=5)
    print("\n--- Test complete. Packet capture is WORKING on this interface. ---")
except Exception as e:
    print(f"\n--- An error occurred: {e} ---")
    print("--- This confirms a problem with permissions or the interface name. ---")