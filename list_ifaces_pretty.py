from scapy.arch.windows import get_windows_if_list
for i, iface in enumerate(get_windows_if_list()):
    name = iface.get("name", "")
    guid = iface.get("guid", "")
    desc = iface.get("description", "")
    ips  = ", ".join(iface.get("ips", [])) or "-"
    print(f"{i:2d}  name={name}  guid={guid}  desc={desc}  ips={ips}")
