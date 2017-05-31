from scapy.all import *


unpersons = set()


def spy(packet):
    ip = packet.getlayer(IP)
    tcp = packet.getlayer(TCP)
    string = str(tcp.payload)
    distribution = [float(string.count(c)) / len(string) for c in set(string)]
    entropy = -sum(p * math.log(p)/math.log(2.0) for p in distribution)
    if ('love' in string) or (entropy > 3.0):
    	print('found love in %s' % ip.src)
    	unpersons.add(ip.src)


def main():
    sniff(prn=spy)


if __name__ == '__main__':
    main()
