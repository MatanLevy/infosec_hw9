from scapy.all import *


def send_message(ip, port):
    message = 'I love you'
    src_port = 65000
    binarystring = ''.join([bin(ord(c))[2:].rjust(8,'0') for c in message])
    length = len(binarystring)
    if (length % 3) > 0:
    	binarystring += '0'*(3 - length % 3)
    tripelength = len(binarystring) / 3
    i = 0
    while i < tripelength:
    	x = i * 3
    	reserved = binarystring[x:x+3]
    	syn_packet = IP(dst = ip) / TCP(sport = src_port,dport = port , flags = 'SA', seq = i, ack = tripelength , reserved = int(reserved,2))
    	send(syn_packet, count = 1)
    	i = i+1




def main():
    send_message('127.0.0.1', 1984)


if __name__ == '__main__':
    main()
