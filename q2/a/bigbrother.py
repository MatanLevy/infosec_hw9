from scapy.all import *


unpersons = set()


def spy(packet):
    ip = packet.getlayer(IP)
    tcp = packet.getlayer(TCP)
    s = str(tcp.payload)
    distribution = [float(s.count(c)) / len(s) for c in set(s)]
    entropy = -sum(p * math.log(p)/math.log(2.0) for p in distribution)
    if 'love' in s or entropy > 3.0:
    	print('found love in %s' % ip.src)
    	unpersons.add(ip.src)


def main():
    sniff(prn=spy)


if __name__ == '__main__':
    main()
