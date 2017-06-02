from scapy.all import *

message = ''
finished = False
x = False
counter = 1

def receive_message(port):
	while not finished:
		sniff(count = 1, prn = on_packet)
	return message	
		
def on_packet(packet):
	global x,message,finished,counter
	if (not packet.haslayer(TCP)):
		return
	tcp = packet.getlayer(TCP)
	src_port = tcp.sport
	flags = tcp.flags
	ack = tcp.ack
	seq = tcp.seq
	reserved = tcp.reserved
	#print("srcport = {0} , flags = {1}, ack = {2}, seq = {3}, reserved = {4}".format(src_port,flags,ack,seq,reserved))
	if (src_port == 65000 and flags == 18):
		if not x:
			x = True
			message = list('0'*ack*3)
		real_inedx = 3 * seq
		message[real_inedx:real_inedx+3] = '{0:03b}'.format(reserved)
		counter += 1
		if (ack == counter):
			finished = True
			message = ''.join(message)
			#print(len(message))
			message = message[:-1]
			print(message)
			message = ''.join(chr(int(message[i*8:i*8+8],2)) for i in range(len(message)//8))
			#print(message)
			return



def main():
    message = receive_message(1984)
    print('received: %s' % message)


if __name__ == '__main__':
    main()
