import scapy.all as scapy
import optparse
import netifaces as netwk

from libraries.color import BColors


def get_arg():
    usage = "usage: %prog [options]"
    parser = optparse.OptionParser(usage=usage)
    parser.add_option("-i", "--ip_address", dest="ip_address", help="Ip address list ")

    (opt, arg) = parser.parse_args()
    if not opt.ip_address:
        parser.error("[-] Please specify an IP address")
    else:
        return opt.ip_address

def local_network_scan():
    # projectSetup()

    interfaces_list = netwk.interfaces()
    print("{} [+] This system has {} interfaces {}".format(BColors.BOLD, len(interfaces_list), BColors.ENDC )
    interfaceNos = list(range(1, len(netwk.interfaces()) + 1))
    netDict = {}
    for iface_name in interfaces_list:
        mm = netwk.ifaddresses(iface_name)
        if 2 in mm.keys() and iface_name != "lo":
            netDict[iface_name] = mm[2][0]
    interface = select_interface_ip(netDict)
    while interface == 0:
        interface = select_interface_ip(netDict)



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


def scan(ip):
    # scapy.arping(ip)
    # arp_req = scapy.ARP()
    arp_req = scapy.ARP(pdst=ip)
    # arp_req.pdst = ip

    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_broadcast = broadcast/arp_req
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
    ip = get_arg()
    scan(ip)

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
