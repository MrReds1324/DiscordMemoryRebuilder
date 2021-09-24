import socket
import os
import signal
import struct
import threading
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA1
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from utils import Connection, Signal, build_data_frame


def get_ip_address():
    # ip = requests.get('https://checkip.amazonaws.com').text.strip()
    return '0.0.0.0'


def handle_handshake(connection: Connection, s_8_bytes: bytes, rsa_public: RSA, rsa_private: RSA) -> bool:
    length = struct.unpack('>I', connection.receive(4))[0]
    received_bytes = connection.receive(length)
    client_key, client_sha1 = received_bytes.split(b':')

    server_sha1 = SHA1.new(client_key).digest()

    if client_sha1 != server_sha1:
        return False

    client_rsa = RSA.importKey(client_key)
    cipher_rsa = PKCS1_OAEP.new(client_rsa)
    encrypted = cipher_rsa.encrypt(s_8_bytes)

    length, message = build_data_frame(rsa_public + b':' + server_sha1 + b':' + encrypted)
    connection.send(length)
    connection.send(message)

    encrypted = connection.receive(8)
    cipher_rsa = PKCS1_OAEP.new(rsa_private)
    c_8_bytes = cipher_rsa.decrypt(encrypted)

    print(f"[!] Server bytes after handshake: {s_8_bytes}")
    print(f"[!] Client bytes after handshake: {c_8_bytes}")

    connection.encryption_key = AES.new(s_8_bytes + c_8_bytes, AES.MODE_CBC, c_8_bytes + s_8_bytes)
    return True


def connection_setup():
    while True:
        try:
            client_socket, address = server.accept()

            print("[!] One client is trying to connect...")
            client = Connection()
            client.socket = client_socket
            client.address = address

            uid_length = struct.unpack('>Q', client.receive(8))[0]
            recieved_uid = client.receive(uid_length)
            client.uid = str(recieved_uid, 'utf-8')

            if handle_handshake(client, server_8_bytes, public_key, private_key):
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


if __name__ == "__main__":
    OPEN_CONNECTIONS = {}

    # Read in stored RSA keys here
    # Otherwise generate new RSA keys here
    key = RSA.generate(2048)
    private_key = key.export_key()
    file_out = open("server_private.pem", "wb")
    file_out.write(private_key)
    file_out.close()

    public_key = key.publickey().export_key()
    file_out = open("server_public.pem", "wb")
    file_out.write(public_key)
    file_out.close()

    server_8_bytes = get_random_bytes(8)
    print(f"[!] Client bytes before handshake: {server_8_bytes}")

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
