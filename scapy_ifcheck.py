from scapy.all import get_if_list
print("Interfaces Scapy can use:")
for i, name in enumerate(get_if_list()):
    print(i, name)
