import clr
clr.AddReference('System')
from System.Net.NetworkInformation import NetworkInterface

def get_ipconfig_info():
    interfaces = NetworkInterface.GetAllNetworkInterfaces()
    info = []
    for iface in interfaces:
        info.append(f"Interface: {iface.Description}")
        if iface.OperationalStatus == 1:
            status = 'Up'
        else:
            status = 'Down'
        info.append(f"  Status: {status}")
        ip_props = iface.GetIPProperties()
        for ip in ip_props.UnicastAddresses:
            if ip.Address.AddressFamily.ToString() == "InterNetwork":
                info.append(f"  IP Address: {ip.Address}")
                info.append(f"  Subnet Mask: {ip.IPv4Mask}")
        info.append("")
    return '\n'.join(info)

if __name__ == "__main__":
    global output
    output = get_ipconfig_info()
    pass