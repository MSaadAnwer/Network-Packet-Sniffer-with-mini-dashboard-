from scapy.all import get_if_list
for i, name in enumerate(get_if_list()):
    print(i, name)
