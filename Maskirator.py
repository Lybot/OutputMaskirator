# -*- coding: utf-8 -*-
import time as t
from socket import *
from threading import Thread
from Config import *
from ParsePacket import *
from multiprocessing import Process


class Maskirator:

    def __init__(self, config_json: ConfigJson):
        self.config = config_json
        self.so = socket(AF_PACKET, SOCK_RAW)
        self.so.setsockopt(SOL_SOCKET, SO_SNDBUF, 15000)
        self.so.bind((self.config.my_config['out_int'], 0x0800, PACKET_OTHERHOST))
        self.si = socket(AF_PACKET, SOCK_RAW)
        self.si.setsockopt(SOL_SOCKET, SO_SNDBUF, 15000)
        self.si.bind((self.config.my_config['in_int'], 0x0800, PACKET_OTHERHOST))
        self.need_change = False
        self.current_link_ip = self.config.get_random_link()
        self.sniff_from_output = Process(target=self.sniff_from_output_int)
        self.sniff_from_output.start()
        self.sniff_from_input = Process(target=self.sniff_from_input_int)
        self.sniff_from_input.start()
        self.update_thread = Thread(target=self.change_link)
        self.update_thread.start()

    def sniff_from_output_int(self):
        while True:
            try:
                packet = self.so.recv(100000)
                if packet:
                    parse_packet = ParsePacket(packet)
                    self.current_link_ip = (parse_packet.get_dst_ip(), parse_packet.get_src_ip())
                    parse_packet.change_mac(self.config.my_config['mask_mac'], self.config.my_config['client_mac'])
                    parse_packet.change_ip(self.config.get_src_ip(parse_packet.get_src_mac()),
                                           self.config.my_config['client_ip'])
                    if len(parse_packet) > 1514:
                        print('big packet')
                        # for i in range(0, parse_packet.__len__(), 1500):
                            # self.si.send(parse_packet.str_packet[i:i+1500])
                    else:
                        self.si.send(parse_packet.str_packet)
                    # self.si.send(parse_packet.str_packet)
            except KeyboardInterrupt:
                sys.exit(1)

    def sniff_from_input_int(self):
        while True:
            try:
                packet = self.si.recv(100000)
                if packet:
                    parse_packet = ParsePacket(packet)
                    need_mac = self.config.get_dst_mac(parse_packet.get_dst_ip())
                    if need_mac is None:
                        pass
                    else:
                        parse_packet.change_mac(self.config.my_config['mask_mac'],
                                                self.config.get_dst_mac(parse_packet.get_dst_ip()))
                        parse_packet.change_ip(self.current_link_ip[0], self.current_link_ip[1])
                        if len(parse_packet) > 1514:
                            print('big packet')
                            # for i in range(0, parse_packet.__len__(), 1500):
                                # self.so.send(parse_packet.str_packet[i:i+1500])
                        else:
                            self.so.send(parse_packet.str_packet)
            except KeyboardInterrupt:
                sys.exit(1)

    def change_link(self):
        while True:
            t.sleep(1)
            self.current_link_ip = self.config.get_random_link()
