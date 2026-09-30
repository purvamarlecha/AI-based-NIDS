from scapy.all import sniff

print("==========================================")
print("       AI-NIDS PACKET CAPTURE TEST")
print("==========================================")

print("\nStarting packet capture...")
print("Capture 10 packets and display them.\n")

packets = sniff(count=10)

print("\n==========================================")
print("          PACKETS CAPTURED")
print("==========================================")

for i, packet in enumerate(packets, start=1):

    print(f"\nPacket {i}")
    print(packet.summary())

print("\n==========================================")
print("       PACKET CAPTURE TEST COMPLETE")
print("==========================================")