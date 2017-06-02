from scapy.all import *
import time
import os

ip_dict = {}
blocked_ip = set()

def on_packet(packet):
	SYN = 0x02
	if (not packet.haslayer(TCP)):
		return
	ip = packet.getlayer(IP).src
	print(ip)
	tcp = packet.getlayer(TCP)
	flags = tcp.flags
	if flags & SYN :
		if is_blocked(ip):
			return
		if (ip_dict.get(ip) is None):
			ip_dict[ip] = []
		currentList = ip_dict.get(ip)
		currentList.append(time.time())
		ip_dict [ip] = currentList
		print('syn detecetd')
		if (cleanLastMinute(ip_dict,ip) > 15):
			os.system('iptables -A INPUT -s %s -j DROP' % ip)
			ip_dict.pop(ip,None)
			blocked_ip.add(ip)


def cleanLastMinute(dict,ip):
	import time
	timeList = dict.get(ip)
	currentTime = int(time.time())
	for time in timeList:
		if currentTime-time > 60:
			timeList.remove(time)
	return len(timeList)

def is_blocked(ip):
    return ip in blocked_ip


def main():
    sniff(prn=on_packet)


if __name__ == '__main__':
    main()
