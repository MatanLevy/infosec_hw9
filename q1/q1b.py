from scapy.all import *
import time
import os

ip_dict = {}

def on_packet(packet):
	SYN = 0x02
	ip = packet.getlayer(IP).src
	tcp = packet.getlayer(TCP)
	flags = tcp.flags
	if flags % SYN :
		ip_dict [ip] = int(time.time())
		print('syn detecetd')
		if (cleanLastMinute(ip_dict,ip) > 15):
			os.system('iptables -A INPUT -s %s -j DROP' % ip)

def cleanLastMinute(dict,ip):
	timeList = dict.get(ip)
	currentTime = int(time.time())
	for time in timeList:
		if currentTime-time > 60:
			timeList.remove(time)
	return len(timeList)

def is_blocked(ip):
    return False # Reimplement me!


def main():
    sniff(prn=on_packet)


if __name__ == '__main__':
    main()
