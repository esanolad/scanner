import scapy.all as scapy
import netifaces as netwk
import requests
from color import BColors
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) #This is supress scapy warnings

def get_mac_details(mac_address):
    # We will use an API to get the vendor details
    url = "https://api.macvendors.com/"

    # Use get method to fetch details
    response = requests.get(url + mac_address)
    if response.status_code != 200:
        return "[!] Invalid!"
    return response.content.decode()



def local_network_scan():
    interfaces_list = netwk.interfaces()
    print("{} [+] This system has {} interfaces {}".format(BColors.BOLD, len(interfaces_list), BColors.ENDC))
    interfaceNos = list(range(1, len(netwk.interfaces()) + 1))
    netDict = {}
    for iface_name in interfaces_list:
        mm = netwk.ifaddresses(iface_name)
        if 2 in mm.keys() and iface_name != "lo":
            netDict[iface_name] = mm[2][0]
    interface = select_interface_ip(netDict)
    while interface == 0:
        interface = select_interface_ip(netDict)


def get_route():
    return scapy.conf.route

def get_ip_summary():
    return scapy.conf.ifaces


def show_ip_route(ip_address):
    return scapy.conf.route.route(ip_address)


def tcp_connect_scan(dst_ip, dst_port, dst_timeout=1):
    """
    :param dst_ip: destination IP address
    :param dst_port: destination post number
    :param dst_timeout: the time to wait after the last packet has been sent
    :return: Open, Closed, Unreachable, CHECK
    """
    src_port = scapy.RandShort() #generates random port number
    resp = scapy.sr1(scapy.IP(dst=dst_ip) / scapy.TCP(sport=src_port, dport=dst_port, flags="S"),
                                      timeout=dst_timeout)
    if str(type(resp)) == "<class 'NoneType'>":
        return "Unreachable"
    elif str(type(resp)) == "<type 'NoneType'>":
        return "Closed"
    elif resp.haslayer(scapy.TCP):
        if resp.getlayer(scapy.TCP).flags == 'SA':  #SYN/ACK is 0x12
            # sends acknowledgement and reset message
            send_rst = scapy.sr(scapy.IP(dst=dst_ip) / scapy.TCP(sport=src_port, dport=dst_port, flags="AR"),
                                timeout=dst_timeout)
            return "Open"
        elif resp.getlayer(scapy.TCP).flags == 'RA': #RST/ACK is 0x14
            return "Closed"
    else:
        return "CHECK"


def stealth_scan(dst_ip, dst_port, dst_timeout):
    """
       :param dst_ip: destination IP address
       :param dst_port: destination post number
       :param dst_timeout: the time to wait after the last packet has been sent
       :return: Open, Closed, Unreachable, CHECK
       """
    src_port = scapy.RandShort()
    resp = scapy.sr1(scapy.IP(dst=dst_ip) / scapy.TCP(sport=src_port, dport=dst_port, flags="S"),
                                  timeout=dst_timeout)

    if str(type(resp)) == "<class 'NoneType'>":
        return "Filtered"
    elif resp.haslayer(scapy.TCP):
        if resp.getlayer(scapy.TCP).flags == 'SA':
            send_rst = scapy.sr(scapy.IP(dst=dst_ip) / scapy.TCP(sport=src_port, dport=dst_port, flags="R"),
                                timeout=dst_timeout)
            return "Open"
        elif resp.getlayer(scapy.TCP).flags == 'RA':
            return "Closed"
    elif resp.haslayer(scapy.ICMP): # check if it receives certain ICMP error messages back
        # ICMP unreachable error (type 3, code 1, 2, 3, 9, 10, or 13)
        if (int(resp.getlayer(scapy.ICMP).type) == 3 and int(
                resp.getlayer(scapy.ICMP).code) in [1, 2, 3, 9, 10, 13]):
            return "Filtered"
    else:
        return "CHECK"


def fin_null_xmas_scan(dst_ip, dst_port, scan_type, dst_timeout=1):

    """
       :param dst_ip: destination IP address
       :param dst_port: destination post number
       :param type: fin,null, xmas
       :param dst_timeout: the time to wait after the last packet has been sent
       :return: Open|Filtered, Closed, Filtered, Unreachable, CHECK
    """
    if scan_type=='fin':
        flag='F'
    elif scan_type=='null':
        flag=''
    elif scan_type =='xmas':
        flag="FPU"
    resp = scapy.sr1(scapy.IP(dst=dst_ip) / scapy.TCP(dport=dst_port, flags=flag), timeout=dst_timeout)
    if str(type(resp)) == "<class 'NoneType'>":
        return "Open|Filtered"
    elif resp.haslayer(scapy.TCP):
        if resp.getlayer(scapy.TCP).flags == 'RA':
            return "Closed"
    elif resp.haslayer(scapy.ICMP):
        if (int(resp.getlayer(scapy.ICMP).type) == 3 and
                int(resp.getlayer(scapy.ICMP).code) in [1, 2, 3, 9, 10, 13]):
            return "Filtered"
    else:
        return "CHECK"


def ack_flag_scan(dst_ip, dst_port, dst_timeout):

    """
        :param dst_ip: destination IP address
        :param dst_port: destination post number
        :param dst_timeout: the time to wait after the last packet has been sent
        :return: filtered, unfiltered, CHECK
     """
    resp = scapy.sr1(scapy.IP(dst=dst_ip) / scapy.TCP(dport=dst_port, flags="A"), timeout=dst_timeout)
    if str(type(resp)) == "<class 'NoneType'>":
        return "Filtered"
    elif resp.haslayer(scapy.TCP):
        if resp.getlayer(scapy.TCP).flags == 'R': #reset flag is set in response
            return "Unfiltered"
    elif resp.haslayer(scapy.ICMP):
        if (int(resp.getlayer(scapy.ICMP).type) == 3 and int(
                resp.getlayer(scapy.ICMP).code) in [1, 2, 3, 9, 10, 13]):
            return "Filtered"
    else:
        return "CHECK"


def window_scan(dst_ip, dst_port, dst_timeout):
    """
        :param dst_ip: destination IP address
        :param dst_port: destination post number
        :param dst_timeout: the time to wait after the last packet has been sent
        :return: no response, closed, open
     """
    resp = scapy.sr1(scapy.IP(dst=dst_ip) / scapy.TCP(dport=dst_port, flags="A"), timeout=dst_timeout)
    if str(type(resp)) == "<class 'NoneType'>":
        return "filtered"
    elif resp.haslayer(scapy.TCP):
        if resp.getlayer(scapy.TCP).window == 0:
            return "closed"
        elif resp.getlayer(scapy.TCP).window > 0:
            return "Open"
    else:
        return "CHECK"



def select_interface_ip(interface_dict):
    selectInterface = {}
    print("Below are the avaialble interfaces on the Machine: ")
    print("\nSN\tINTERFACE\t\t IP ADDRESS \t\t NETMASK \t\t BROADCAST ADDRESS\n", "-" * 100)
    count = 1
    for intName in interface_dict:
        print("{}. \t {:<15} \t{:<15} \t{:<15} \t{:15}".format(count, intName, interface_dict[intName]['addr'],
                                                               interface_dict[intName]['netmask'],
                                                               interface_dict[intName]['broadcast']))
        selectInterface[count] = interface_dict[intName]
        count += 1
    try:
        selectNos = int(input("Please Select an interface number to use:"))
        # print(selectInterface[selectNos])
        return selectInterface[selectNos]
    except KeyError:
        print("Menu must be between 1 and", count)
        return 0
    except ValueError:
        print("Menu must be an integer between 0-3")
        return 0


def scan_interface():
    return 0


def scan(ip):
    # scapy.arping(ip)
    # arp_req = scapy.ARP()
    arp_req = scapy.ARP(pdst=ip)
    # arp_req.pdst = ip

    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_broadcast = broadcast / arp_req
    # ans, unans = scapy.srp(arp_req_broadcast, timeout=1)
    ans = scapy.srp(arp_req_broadcast, timeout=1)[0]

    host_list = []
    for item in ans:
        host = {"IP": item[1].psrc, "MAC": item[1].src}
        host_list.append(host)
    return host_list

    # scapy.ls(scapy.ARP())
    # scapy.ls(arp_req)
    # scapy.ls(broadcast)
    # scapy.ls(arp_req_broadcast)

    # print(arp_req.summary())
    # print(arp_req_broadcast.summary())
    # print(ans.summary())
    # print(unans.summary())

    # broadcast.show()
    # arp_req.show()
    # arp_req_broadcast.show()
    # ans.show()
    # ans.summary(lambda s, r: r.sprintf("%pdst% has the MAC address: %hwsrc%"))


if __name__ == '__main__':
    #ip = get_arg()
    #print(scan(ip))
    #print(tcp_connect_scan('192.168.98.134',80,2))
    print(fin_null_xmas_scan('192.168.98.134',800,'xmas'))

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
