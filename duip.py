import os
from scapy.all import *
import scapy.all as scapy
import sys
import csv
from time import strftime, localtime

# f = open('log/dealpcap.log', 'a') #日志的重定向输出
# sys.stdout = f
# sys.stderr = f

print(strftime("%Y-%m-%d %H:%M:%S", localtime())+"开始处理")

fp = open("./log/2021-05-25.log")
malware_ip =set()
for line in fp.readlines():  # 遍历每一行
    date_str = line[43:81]  # 每行取前14个字母，作为下面新建文件的名称
    # content = line[14:]  # 每行取第15个字符后的所有字符，作为新建文件的内容
    ip = date_str.split(" ")
    # ipv4 = ip[0]
    malware_ip.add(ip[0])

fp.close()

srccapfile = './data_flow/5_25_flow.pcap'
malware_pcap = './malware_flow/test.pcap'

# pr = PcapReader(srccapfile) #逐行读取package包
# packet = pr.read_packet()
id = 0
pkts = rdpcap(srccapfile)
for pkt in pkts:

# while (packet): #如何判断读取结束
    print("pcaket id:",id)
    # packet = pr.read_packet()

    if (pkt.payload.name == "IP"):
        source = pkt.payload.src
        destination = pkt.payload.dst
        for ip in malware_ip:
            if (source == ip or destination == ip):
                scapy.wrpcap(malware_pcap, pkt, append=True)

    id=id+1

    # try:
    #    packet= pr.read_packet() #读取下一个package包
    # except EOFError:
    #    print("no more pcap")
    #    break
