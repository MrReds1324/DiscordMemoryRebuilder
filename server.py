import socket
import os
import signal
import struct
from threading import Thread, Lock
import time

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from utils import Connection, Signal, encrypt_data_to_data_frame, decrypt_message

MAX_RETRIES = 10


def get_ip_address():
    # ip = requests.get('https://checkip.amazonaws.com').text.strip()
    return '0.0.0.0'


def handle_handshake(connection: Connection, s_8_bytes: bytes, rsa_public: RSA, rsa_private: RSA) -> bool:
    return True


def connection_setup(connection_lock: Lock):
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
                with connection_lock:
                    OPEN_CONNECTIONS[client.uid] = client

                received_signal = client.receive(7)
                if received_signal == Signal.READY:
                    print(f'[!] Client with uid {client.uid} is ready for data')
            else:
                print(f'[!] Client with uid {client.uid} failed to properly exchange key information with the server')
                client.close()

        except ConnectionResetError:
            print('[!] Client connection was reset')

        except struct.error:
            print('[!] Failed to unpack uid size')


def send_data_frame(connection: Connection, message: str, connection_lock: Lock, retry: int = 0) -> bool:
    if MAX_RETRIES == retry:
        return False

    try:
        # Encrypt the message and send it to the server
        message_length, encrypted_message = encrypt_data_to_data_frame(bytes(message, 'utf-8'), connection.encryption_key)
        connection.send(message_length)
        connection.send(encrypted_message)

        # Listen for the AWAIT, or RESEND signal before continuing
        message_len_bytes = connection.receive(4)
        message_len = struct.unpack('>I', message_len_bytes)[0]
        message_bytes = connection.receive(message_len)

        decrypted_message_bytes = decrypt_message(message_bytes, connection.encryption_key)

        # If the decrypted message is the AWAIT signal return True, otherwise attempt to resend the message 10 times
        if decrypted_message_bytes == Signal.AWAIT:
            return True
        elif decrypted_message_bytes == Signal.RESEND:
            return send_data_frame(connection, message, connection_lock, retry + 1)

    except ConnectionResetError:
        print('[!] Failed to send message to client because client connection was reset')
        # Remove the client from the OPEN_CONNECTIONS here if it fails to connect
        with connection_lock:
            connection.close()
            del OPEN_CONNECTIONS[connection.uid]
        return False


if __name__ == "__main__":
    # Accessing/Modifying the OPEN_CONNECTIONS dictionary is not thread_safe so will need to lock access/modifications
    _lock = Lock()
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
    threading_accept = Thread(target=connection_setup, args=[_lock])
    threading_accept.start()

    time.sleep(5)
    while len(OPEN_CONNECTIONS.values()) == 0:
        pass

    # We actually do not need to send anything using threading as each client must go before the other so we can just single thread this portion
    # and handle if a client disconnects
    for conn in OPEN_CONNECTIONS.values():
        send_data_frame(conn, 'testing', _lock)

    while True:
        pass
