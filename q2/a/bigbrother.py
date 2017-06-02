from scapy.all import *


unpersons = set()


def spy(packet):
    ip = packet.getlayer(IP)
    tcp = packet.getlayer(TCP)
    s = str(tcp.payload)
    if 'love' in s:
    	#print('found love in %s' % ip.src)
    	unpersons.add(ip.src)


def main():
    sniff(prn=spy)


if __name__ == '__main__':
    main()
