from scapy.all import *

defined_size = False
message = ''
finished = False
x = False

def receive_message(port):
	while not finished:
		sniff(count = 1, prn = on_packet)
	return message	
		
def on_packet(packet):
	global x,message
	tcp = packet.getlayer(TCP)
	src_port = tcp.sport
	flags = tcp.flags
	ack = tcp.ack
	seq = tcp.seq
	reserved = tcp.reserved
	print("srcport = {0} , flags = {1}, ack = {2}, seq = {3}, reserved = {4}".format(src_port,flags,ack,seq,reserved))
	if (src_port == 65000 and flags == 18):
		if not x:
			x = True
			message = list('0'*ack)
		message[seq:seq+3] = '101'
		if (ack == 1):
			finished = True
			message = ''.join(message)
			print(message)
			message = ''.join(chr(int(message[i*8:i*8+8],2)) for i in range(len(message)//8))



def main():
    message = receive_message(1984)
    print('received: %s' % message)


if __name__ == '__main__':
    main()
