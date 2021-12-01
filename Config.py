from json import *
import sys
import random


class ConfigJson:

    def __init__(self, file_path, ips):
        file = open(file_path)
        json = load(file)
        file.close()
        self.maskirators = json['maskirators']
        self.fake_structure = json['fake_structure']
        self.my_config = None
        self.random_seq = None
        self.set_my_config(ips)
        self.generate_random_seq()

    def set_my_config(self, ips):
        for ip in ips:
            mask = self.find_maskirator(ip=ip)
            if mask is not None:
                self.my_config = mask
                break

    def my_ip(self):
        return self.my_config["mask_ip"]

    def client_ip(self):
        return self.maskirators["client_ip"]

    def get_src_ip(self, mac):
        mask = self.find_maskirator(mac=mac)
        return mask["client_ip"]

    def get_dst_mac(self, ip):
        for maskirator in self.maskirators:
            if maskirator['client_ip'] == ip:
                return maskirator['mask_mac']

    def find_maskirator(self, ip=None, mac=None):
        if (ip is None) & (mac is None):
            return None
        if ip is None:
            for maskirator in self.maskirators:
                if maskirator['mask_mac'] == mac:
                    return maskirator
        if mac is None:
            for maskirator in self.maskirators:
                if maskirator['mask_ip'] == ip:
                    return maskirator
            return None

    def generate_random_seq(self):
        host_seq = []
        current_host_chance = 0
        for host in self.fake_structure:
            host_object = {"interval": None, "links_intervals": None}
            current_host_chance += host['chance'] * 100
            host_object["interval"] = current_host_chance
            link_seq = []
            current_link_chance = 0
            for link in host["link_addresses"]:
                current_link_chance += link["chance"] * 100
                link_seq.append(current_link_chance)
            host_object["links_intervals"] = link_seq
            host_seq.append(host_object)
        self.random_seq = host_seq

    def get_random_link(self):
        rand_host = random.randint(0, 99)
        host_number = 0
        for host in self.random_seq:
            if host["interval"] > rand_host:
                rand_link = random.randint(0, 99)
                link_number = 0
                for link in host["links_intervals"]:
                    if link > rand_link:
                        return self.fake_structure[host_number]["host_ip"], self.fake_structure[host_number]["link_addresses"][link_number]["ip"]
                    link_number += 1
            host_number += 1
