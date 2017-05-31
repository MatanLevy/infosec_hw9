import socket
from crypto import CryptoMessage

key = 'matanlevykey1234'

def send_message(ip, port):
    message = 'I love you'
    encMessage = CryptoMessage(key).encrypt(message)
    connection = socket.socket()
    try:
        connection.connect((ip, port))
        connection.send(encMessage)
    finally:
        connection.close()


def main():
    send_message('127.0.0.1', 1984)


if __name__ == '__main__':
    main()
