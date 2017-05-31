from scapy.all import *
#import errno
#from socket import error as socket_error
import socket


def stealth_syn_scan(ip, ports, timeout):
	SYN = 0x02
	ACK = 0x10
	RST = 0x04
	result = []
	for port in ports:
		syn_packet = IP(dst = ip) / TCP(dport = port , flags = 'S')
		answer = sr1(syn_packet, timeout = timeout)
		if (answer is None) :
			result.append("filtered")
		else : 
			flags = answer.getlayer(TCP).flags
			if ((SYN & flags) and (ACK & flags)):
				result.append("opened")
			if (RST & flags):
				result.append("closed")
	return result



def main(argv):
    if not 3 <= len(argv) <= 4:
        print('USAGE: %s <ip> <ports> [timeout]' % argv[0])
        return 1
    ip    = argv[1]
    ports = [int(port) for port in argv[2].split(',')]
    if len(argv) == 4:
        timeout = int(argv[3])
    else:
        timeout = 5
    results = stealth_syn_scan(ip, ports, timeout)
    for port, result in zip(ports, results):
        print('port %d is %s' % (port, result))


if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv))
