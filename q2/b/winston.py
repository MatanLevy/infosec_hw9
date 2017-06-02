from scapy.all import *


def send_message(ip, port):
    message = 'I love you'
    src_port = 65000
    binarystring = ''.join([bin(ord(c))[2:].rjust(8,'0') for c in message])
    print binarystring
    tripelength = len(binarystring) / 3
    if (len(binarystring) % 3 > 0):
    	tripelength += 1
    i = 0
    print tripelength
    while i < tripelength:
    	x = i * 3
    	print x
    	print binarystring[x:x+3]
    	reserved = binarystring[x:x+3]
    	syn_packet = IP(dst = ip) / TCP(sport = src_port,dport = port , flags = 'SA', seq = i, ack = tripelength , reserved = int(reserved,2))
    	send(syn_packet, count = 1)
    	i = i+1




def main():
    send_message('127.0.0.1', 1984)


if __name__ == '__main__':
    main()
