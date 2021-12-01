# -*- coding: utf-8 -*-
from socket import *
import os
import sys
import re
import json
import pickle
import subprocess as sp
from PyQt4 import QtCore, QtGui, uic
import random as r
import threading
import time
from select import select
from multiprocessing import Process
class ParsePacket:
    @classmethod
    def set_frag_offset(cls, pack, offset, mf):
        m = offset % 256
        n = offset >> 8
        n += (mf << 5) + (1 << 6)

        if n > 255:
            print("n > 255")
        if m > 255:
            print("m > 255")
        offset = chr(n) + chr(m)
        pack = pack.replace(pack[20:22], offset)
        return pack

    @classmethod
    def set_frag_size(cls,pack, size):
        m = size % 256
        n = size >> 8
        size = chr(n) + chr(m)
        pack = pack.replace(pack[16:18], size)
        return pack
    @classmethod
    def set_ip_id(cls, pack, ip_id):
        m = ip_id % 256
        n = ip_id >> 8
        ip_id = chr(n) + chr(m)
        pack = pack.replace(pack[18:20], ip_id)
        return pack
    def frag_ip(pack, size):
        ip_head = pack.str_packet[:34]
        data = pack.str_packet[34:]
        el_offset = size / 8
        size = (el_offset) * 8
        n = len(data) / size + 1
        frags = list()
        offset = 0
        for i in range(n):
            frag = data[i * size:(i + 1) * size]
            frag_size = len(frag) + 20
            ip_head = ParsePacket.set_frag_size(ip_head, frag_size)
            if i == n - 1:
                ip_head = ParsePacket.set_frag_offset(ip_head, offset, 0)
            else:
                ip_head = ParsePacket.set_frag_offset(ip_head, offset, 1)
            frags.append(ip_head + frag)
            offset += el_offset
        return frags
    def __init__(self, str_packet):
        self.str_packet = str_packet
        # self.src_ip = str_packet[26:30]
        # self.dst_ip = str_packet[30:34]
        # self.src_mac = str_packet[0:6]
        # self.dst_mac = str_packet[6:12]
    def change_mac(self, src_mac, dst_mac):
        self.str_packet = self.str_packet.replace(self.str_packet[0:12], bytes.fromhex(dst_mac.replace(":","")) + bytes.fromhex(src_mac.replace(":","")))
    def change_ip(self, src_ip, dst_ip):
        def str_to_hex_ip(ip):
            ip_numbers = ip.split('.')
            result = []
            for number in ip_numbers:
                 result.append(int(number))
            byte_result = bytes(result)
            return byte_result
        self.str_packet= self.str_packet.replace(self.str_packet[26:34], str_to_hex_ip(src_ip)+ str_to_hex_ip(dst_ip))
    def get_src_ip(self):
        src_ip = ""
        for number in self.src_ip:
            src_ip += str(int(number.encode('hex'),16)) + "."
        src_ip = src_ip[0:(len(src_ip)-1)]
        return src_ip
    def get_dst_ip(self):
        dst_ip = ""
        for number in self.dst_ip:
            dst_ip += str(int(number.encode('hex'),16)) + "."
        dst_ip = dst_ip[0:(len(dst_ip)-1)]
        return dst_ip
    def __str__(self):
        result = self.str_packet
        return result
    def __len__(self):
        return len(self.str_packet)
#функция выполнения команды в оболочке
def exec_com(command_string):
    p = sp.Popen(command_string, shell=True, stdout=sp.PIPE, stderr=sp.PIPE)
    out, err = str(p.stdout.read()), str(p.stderr.read())
    return out, err #возвращает вывод оболочки и ошибку
def get_mac(ip):
    mac_command, err = exec_com("arp "+ip)
    mac = re.findall(r"(..:..:..:..:..:..)", mac_command)[0]
    return mac
def get_my_mac(eth):
    mac_command, err = exec_com("ifconfig  "+eth)
    mac = re.findall(r"(..:..:..:..:..:..)", mac_command)[0]
    return mac
def sniff_from_output_int():
    while True:
        try:
            packet = so.recv(2000)
            if packet:
                parse_packet = ParsePacket(packet)
                parse_packet.change_mac(this_mask_in_mac, client_mac)
                parse_packet.change_ip(other_client_ip, my_client_ip)
                if len(parse_packet)>1514:
                    print(len(parse_packet))
                else:
                    si.send(parse_packet.str_packet)
        except KeyboardInterrupt:
            os._exit(0)
def sniff_from_input_int():
    while True:
        try:
            packet = si.recv(2000)
            if packet:
                parse_packet = ParsePacket(packet)
                parse_packet.change_mac(this_mask_out_mac, other_mask_out_mac)
                parse_packet.change_ip("200.164.32.12", "201.34.66.12")
                if len(parse_packet)>1514:
                    print(len(parse_packet))
                else:
                    so.send(parse_packet.str_packet)
        except KeyboardInterrupt:
            os._exit(0)
def send_out_socket():
    while True:
        if len(send_so)>0:
            socket_out_send.send(send_so.pop(0))
def send_in_socket():
    while True:
        if len(send_si)>0:
            socket_in_send.send(send_si.pop(0))
so = socket(AF_PACKET, SOCK_RAW)
#so.setsockopt(SOL_SOCKET, SO_RCVLOWAT,100)
so.bind(('eth0', 0x0800, PACKET_OTHERHOST))
si = socket(AF_PACKET, SOCK_RAW)
#si.setsockopt(SOL_SOCKET, SO_RCVLOWAT,100)
si.bind(('eth1', 0x0800, PACKET_OTHERHOST))
global client_mac
global other_mask_out_mac
global this_mask_out_mac
global this_mask_in_mac
global my_in_ip
global my_out_ip
global other_mask_ip
global other_client_ip
global my_client_ip
if sys.argv[1]=="1":
    my_in_ip = "192.168.1.1"
    my_out_ip = "200.168.2.1"
    my_client_ip = "192.168.1.2"
    other_client_ip = "192.168.3.2"
    other_mask_ip= "200.168.2.2"
    client_mac = get_mac(my_client_ip)
    other_mask_out_mac = get_mac(other_mask_ip)
    this_mask_out_mac = get_my_mac("eth0")
    this_mask_in_mac = get_my_mac("eth1")
elif sys.argv[1]=="2":
    my_in_ip = "192.168.3.1"
    my_out_ip = "200.168.2.2"
    my_client_ip = "192.168.3.2"
    other_client_ip = "192.168.1.2"
    other_mask_ip= "200.168.2.1"
    client_mac = get_mac(my_client_ip)
    other_mask_out_mac = get_mac(other_mask_ip)
    this_mask_out_mac = get_my_mac("eth0")
    this_mask_in_mac = get_my_mac("eth1")
else:
    print("add arg: 1 - role or 2 - role")
    os._exit(0)
sniff_from_output = Process(target = sniff_from_output_int)
sniff_from_output.start()
sniff_from_input = Process(target = sniff_from_input_int)
sniff_from_input.start()
# if sniff_from_output !=0:
#     sniff_from_output_int()
# sniff_from_output.start()
# sniff_from_input = threading.Thread(target=sniff_from_input_int)
# sniff_from_input.daemon = True
# sniff_from_input.start()
# sniff_from_input = os.fork()
# if sniff_from_input!=0:
#     sniff_from_input_int()
while True:
    try:
        print("works")
        time.sleep(10)
    except KeyboardInterrupt:
        os._exit(0)