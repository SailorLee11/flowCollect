import os
from scapy.all import *
import scapy.all as scapy
import sys
import csv
from time import strftime, localtime

# f = open('log/dealpcap.log', 'a') #日志的重定向输出
# sys.stdout = f
# sys.stderr = f

# print(strftime("%Y-%m-%d %H:%M:%S", localtime())+"开始处理")

# 需要采集的数据包
srccapfile = './data_flow/5_25_flow.pcap'
# 需要保存的pcap包
malware_pcap = './malware_flow/test2.pcap'



def main_process():
    print(strftime("%Y-%m-%d %H:%M:%S", localtime()) + "开始处理log")
    fp = open("./log/2021-05-25.log")
    malware_ip = []
    for line in fp.readlines():  # 遍历每一行
        date_str = line.split(" ")  # 每行取前14个字母，作为下面新建文件的名称
        # content = line[14:]  # 每行取第15个字符后的所有字符，作为新建文件的内容
        # ip = date_str.split(" ")
        # ipv4 = ip[0]
        col = []
        col.append(date_str[3])
        col.append(date_str[4])
        col.append(date_str[6])
        malware_ip.append(col)

    fp.close()
    print(strftime("%Y-%m-%d %H:%M:%S", localtime()) + "log处理完毕,开始读取pcap！")




    # pr = PcapReader(srccapfile) #逐行读取package包
    # packet = pr.read_packet()
    id = 0
    pkts = scapy.rdpcap(srccapfile)
    print(strftime("%Y-%m-%d %H:%M:%S", localtime()) + "pcap已经读入内存中，开始提取！")
    for pkt in pkts:
        print("pcaket id:",id)
        # if (pkt.payload.name == "IP"):
        source = pkt.payload.src
        destination = pkt.payload.dst
        s_port = pkt.payload.sport
        d_port = pkt.payload.dport
        for ip in malware_ip:
            if(source == ip[0]):
                if(s_port == ip[1] and d_port == ip[2]):
                    scapy.wrpcap(malware_pcap, pkt, append=True)

            elif (destination == ip[0]):
                    if(s_port == ip[2] and d_port == ip[1]):
                        scapy.wrpcap(malware_pcap, pkt, append=True)

        id=id+1
        # if(pkt.payload.name == "TCP"):
        #     t_sprot = pkt.s

if __name__ == '__main__':

    # pkts = rdpcap('malware_flow/test.pcap')
    # for pkt in pkts:
    #     pkt.show()
    #     source = pkt.payload.src
    #     destination = pkt.payload.dst
    #     s_port = pkt.payload.sport
    #     d_port = pkt.payload.dport
    # packet = pr.read_packet()
    #
    # print(packet.payload.dport)
    main_process()