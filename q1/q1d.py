from scapy.all import *




def on_packet(packet):
	SYN = 0x02
	if not packet.haslayer(TCP):
		return
	ip = packet.getlayer(IP)
	if (packet.haslayer(IP) and ip.dst == '10.0.2.15'):
		return
	tcp = packet.getlayer(TCP)
	flags = tcp.flags
	if (SYN & flags):
		response = IP(dst = ip.src, src = ip.dst) / TCP(sport = tcp.dport ,dport = tcp.sport,flags = "SA")
		print response.summary()
		send(response)





def main():
    sniff(prn=on_packet)


if __name__ == '__main__':
    main()