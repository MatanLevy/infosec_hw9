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
	tcp = packet.getlayer(TCP)
	flags = tcp.flags
	if flags & SYN :
		if is_blocked(ip):
			return     #ignore
		if (ip_dict.get(ip) is None):
			ip_dict[ip] = []   #create a new list of times
		currentList = ip_dict.get(ip)
		currentList.append(time.time()) #enter current time to list
		ip_dict [ip] = currentList
		if (cleanLastMinute(ip_dict,ip) > 15):
			os.system('iptables -A INPUT -s %s -j DROP' % ip)
			ip_dict.pop(ip,None)
			blocked_ip.add(ip)

'''updating list by last 60 seconds and return number of element after the update
	this number will be the number of syn got for this IP in the last minute'''
def cleanLastMinute(dict,ip):
	import time
	timeList = dict.get(ip)
	currentTime = int(time.time())
	for time in timeList:
		if currentTime-time > 60: #old time-remove it from the list
			timeList.remove(time)
	return len(timeList)

def is_blocked(ip):
    return ip in blocked_ip


def main():
    sniff(prn=on_packet)


if __name__ == '__main__':
    main()
