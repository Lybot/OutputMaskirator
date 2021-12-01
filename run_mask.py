from Maskirator import *
import subprocess as sp
from Config import *
import re


# функция выполнения команды в оболочке
# def get_mac(ip):
#     mac_command, err = exec_com("arp "+ip)
#     mac = re.findall(r"(..:..:..:..:..:..)", mac_command)[0]
#     return mac
# def get_my_mac(eth):
#     mac_command, err = exec_com("ifconfig  "+eth)
#     mac = re.findall(r"(..:..:..:..:..:..)", mac_command)[0]
#     return mac


def exec_com(command_string):
    p = sp.Popen(command_string, shell=True, stdout=sp.PIPE, stderr=sp.PIPE)
    out, err = str(p.stdout.read()), str(p.stderr.read())
    return out, err
    # возвращает вывод оболочки и ошибку


cmd = exec_com("ifconfig")[0]
ips = re.findall(r'(\d+\.\d+\.\d+\.\d+)', cmd)
config = ConfigJson("config.json", ips)
maskirator = Maskirator(config)
while True:
    t.sleep(5)
    print("Working...")
