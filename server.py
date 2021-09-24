import socket
import os
import signal
import struct
import threading
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from utils import Connection, Signal


def get_ip_address():
    # ip = requests.get('https://checkip.amazonaws.com').text.strip()
    return '0.0.0.0'


def handle_handshake(connection: Connection, s_8_bytes: bytes, rsa_public: RSA, rsa_private: RSA) -> bool:
    return True


def connection_setup():
    while True:
        try:
            client_socket, address = server.accept()  # This is a blocking call

            print("[!] One client is trying to connect...")
            client = Connection()
            client.socket = client_socket
            client.address = address

            uid_length = struct.unpack('>Q', client.receive(8))[0]
            recieved_uid = client.receive(uid_length)
            client.uid = str(recieved_uid, 'utf-8')

            if handle_handshake(client, server_8_bytes, None, None):
                print(f'[!] Client with uid {client.uid} has connected and is now registered')
                # Once we have completed the handshake, register the connection under the uid
                OPEN_CONNECTIONS[client.uid] = client

                received_signal = client.receive(7)
                if received_signal == Signal.READY:
                    print(f'[!] Client with uid {client.uid} is ready for data')
                    while True:
                        client.send(b'1')
            else:
                print(f'[!] Client with uid {client.uid} failed to properly exchange key information with the server')
                client.close()

        except ConnectionResetError:
            print('[!] Client connection was reset')

        except struct.error:
            print('Failed to unpack uid')


def send_data_frames():
    pass


if __name__ == "__main__":
    OPEN_CONNECTIONS = {}

    # Read in stored RSA keys here
    # with open('server_private.pem', 'rb'):
    #     pass
    # with open('server_public.pem', 'rb'):
    #     pass
    # Otherwise generate new RSA keys here

    server_8_bytes = get_random_bytes(8)

    host = get_ip_address()
    port = 8080

    print(f"[!] Server IP {host} & PORT {port}")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(1)

    print("[!] Server Connection Successful\n")

    # accept clients
    threading_accept = threading.Thread(target=connection_setup)
    threading_accept.start()

    while True:
        pass
