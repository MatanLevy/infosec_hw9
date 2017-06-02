from scapy.all import *


''' global variables to implement recive data '''
message = '' #the final message sent from winston
finished = False # True only when finish reciveing all data
size_defined = False #boolean variable to check if we got the first packet from winston(and so can define the length of message)
counter = 0 #count the number of messages from winston

def receive_message(port):
	while not finished:
		sniff(count = 1, prn = on_packet)
	return message	
		
def on_packet(packet):
	global size_defined,message,finished,counter
	if (not packet.haslayer(TCP)):
		return
	tcp = packet.getlayer(TCP)
	src_port = tcp.sport
	flags = tcp.flags
	ack = tcp.ack
	seq = tcp.seq
	reserved = tcp.reserved
	if (src_port == 65000 and flags == 18):
		if not size_defined:
			#this happen only one time,in the first packet
			size_defined = True
			message = list('0'*ack*3)
		real_inedx = 3 * seq
		message[real_inedx:real_inedx+3] = '{0:03b}'.format(reserved) #updating data from winston
		counter += 1
		if (ack == counter): #happen only one time,in the end
			finished = True
			message = ''.join(message)
			message = ''.join(chr(int(message[i*8:i*8+8],2)) for i in range(len(message)//8)) #convert to string,taken from stackoverflow
			return



def main():
    message = receive_message(1984)
    print('received: %s' % message)


if __name__ == '__main__':
    main()
