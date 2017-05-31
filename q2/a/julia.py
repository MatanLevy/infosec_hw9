import socket
from crypto import CryptoMessage


key = 'matanlevykey1234'

def receive_message(port):
    listener = socket.socket()
    try:
        listener.bind(('', port))
        listener.listen(1)
        connection, address = listener.accept()
        try:
            encmsg = connection.recv(1024)
            decmsg = CryptoMessage(key).decrypt(encmsg)
            return decmsg
        finally:
            connection.close()
    finally:
        listener.close()


def main():
    message = receive_message(1984)
    print('received: %s' % message)


if __name__ == '__main__':
    main()
