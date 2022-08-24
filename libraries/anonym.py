# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.

import subprocess
import re
import optparse
import os


from libraries.color import BColors


def get_arg():
    usage = "usage: %prog [options]"
    parser = optparse.OptionParser(usage=usage)
    parser.add_option("-i", "--interface", dest="interface", help="Interface to change its Mac")
    parser.add_option("-m", "--mac", dest="new_mac", help="New Mac address")
    (opt, args) = parser.parse_args()
    if not opt.new_mac:
        parser.error("[-] Please specify a Mac address")

    elif not opt.interface:
        parser.error("[-] Please specify an Interface")

    else:
        return parser.parse_args()




def get_current_mac(interface):
    result = subprocess.check_output(["ifconfig", interface])
    ss = re.search("\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(result))
    if ss:
        return ss.group(0)
    else:
        print("[-] Current MAC cannot be read")


def change_mac(eth, mac):
    ss = re.search("^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", mac)
    if ss:
        print("[+] Bringing Interface down... {} [OK] {}".format(BColors.OKGREEN, BColors.ENDC))
        subprocess.call(["ifconfig", eth, "down"])
        print("[+] Changing MAC Address...  {} [OK] {}".format(BColors.OKGREEN, BColors.ENDC))
        subprocess.call(["ifconfig", eth, "hw", "ether", mac])
        print("[+] Binging Interface up... {} [OK] {}".format(BColors.OKGREEN, BColors.ENDC))
        subprocess.call(["ifconfig", eth, "up"])
        # subprocess.call(["ifconfig"])
    else:
        print("Not a MAC Address")


# Press the green button in the gutter to run the script.

if __name__ == '__main__':

    (opts, arg) = get_arg()
    if not os.geteuid():
        current_mac = get_current_mac(opts.interface)
        print("[+] Current MAC is: {} {} {} {}".format(BColors.BOLD, BColors.OKGREEN, current_mac, BColors.ENDC))
        change_mac(opts.interface, opts.new_mac)
        current_mac = get_current_mac(opts.interface)
        print("[+] New MAC is: ", current_mac)
    else:
        print("{} {} [-] You need root access to run this command {} ".format(BColors.FAIL, BColors.BOLD, BColors.ENDC))
