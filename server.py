import socket
import csv
import os
import struct
import sys
import time
import json
import argparse
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA1
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from threading import Thread, Lock
from typing import List
from utils import Connection, Signal, encrypt_data_to_data_frame, decrypt_message, build_data_frame

MAX_RETRIES = 10


def get_ip_address():
    # ip = requests.get('https://checkip.amazonaws.com').text.strip()
    return '0.0.0.0'


def handle_handshake(connection: Connection, s_8_bytes: bytes, rsa_public: RSA, rsa_private: RSA) -> bool:
    length = int.from_bytes(connection.receive(4), byteorder='big')
    received_bytes = connection.receive(length)
    client_key = received_bytes[:-20]
    client_sha1 = received_bytes[-20:]

    server_sha1 = SHA1.new(client_key).digest()

    if client_sha1 != server_sha1:
        return False

    client_rsa = RSA.importKey(client_key)
    cipher_rsa = PKCS1_OAEP.new(client_rsa)
    encrypted = cipher_rsa.encrypt(s_8_bytes)

    length, message = build_data_frame(rsa_public + server_sha1)
    connection.send(length)
    connection.send(message)

    length, message = build_data_frame(encrypted)
    connection.send(length)
    connection.send(message)

    length = int.from_bytes(connection.receive(4), byteorder='big')
    encrypted = connection.receive(length)
    private_rsa_key = RSA.importKey(rsa_private)
    cipher_rsa = PKCS1_OAEP.new(private_rsa_key)
    c_8_bytes = cipher_rsa.decrypt(encrypted)

    connection.encryption_key = AES.new(s_8_bytes + c_8_bytes, AES.MODE_CBC, c_8_bytes + s_8_bytes)
    return True


def connection_setup(client_list: List[str], connection_lock: Lock):
    while True:
        try:
            client_socket, address = server.accept()  # This is a blocking call

            print('[!] One client is trying to connect...')
            client = Connection()
            client.socket = client_socket
            client.address = address

            uid_length = struct.unpack('>Q', client.receive(8))[0]
            recieved_uid = client.receive(uid_length)
            client.uid = str(recieved_uid, 'utf-8')

            # If the client uid is not valid then close the connection
            # if client.uid not in client_list:
            #     print('[!] Client did not connect with a valid uid. Ending connection...')
            #     client.close()
            #     continue

            if handle_handshake(client, server_8_bytes, public_key, private_key):
                print(f'[!] Client with uid {client.uid} has connected and is now registered')
                # Once we have completed the handshake, register the connection under the uid
                with connection_lock:
                    OPEN_CONNECTIONS[client.uid] = client

                received_signal = client.receive(7)
                if received_signal == Signal.READY:
                    print(f'[!] Client with uid {client.uid} is ready for data\n')
            else:
                print(f'[!] Client with uid {client.uid} failed to properly exchange key information with the server')
                client.close()

        except ConnectionResetError:
            print('[!] Client connection was reset')

        except OSError:
            return

        except struct.error:
            print('[!] Failed to unpack uid size')


def send_data_frame(connection: Connection, message: str, connection_lock: Lock, retry: int = 0, wait_for_reply: bool = True) -> bool:
    if MAX_RETRIES == retry:
        # Remove the client from the OPEN_CONNECTIONS here if we have failed to properly send the data and force it to reconnect
        with connection_lock:
            connection.close()
            del OPEN_CONNECTIONS[connection.uid]
        return False

    try:
        # Encrypt the message and send it to the server
        message_length, encrypted_message = encrypt_data_to_data_frame(bytes(message, 'utf-8'), connection.encryption_key)
        connection.send(message_length)
        connection.send(encrypted_message)

        # Listen for the AWAIT, or RESEND signal before continuing
        if wait_for_reply:
            message_len_bytes = connection.receive(4)
            message_len = struct.unpack('>I', message_len_bytes)[0]
            message_bytes = connection.receive(message_len)

            decrypted_message_bytes = decrypt_message(message_bytes, connection.encryption_key)

            # If the decrypted message is the AWAIT signal return True, otherwise attempt to resend the message 10 times
            if decrypted_message_bytes == Signal.AWAIT:
                return True
            elif decrypted_message_bytes == Signal.RESEND:
                return send_data_frame(connection, message, connection_lock, retry + 1, wait_for_reply)

    except ConnectionResetError:
        print(f'[!] Failed to send message to client {connection.uid} because client connection was reset')
        # Remove the client from the OPEN_CONNECTIONS here if it fails to connect
        with connection_lock:
            connection.close()
            del OPEN_CONNECTIONS[connection.uid]
        return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Load a file full of message to be sent to each client, keyed by their uid, and a '
                                                 'server config which gives which client uids need to connect')
    #parser.add_argument('-m', '--messages', type=str, required=True, help='Full path to the all_message.csv file containing the set of messages to be sent')
    #parser.add_argument('-c', '--config', type=str, required=True, help='Full path to the input config for the server client uids')

    args = parser.parse_args()

    c_list = []

    # generate new RSA keys
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    # if not os.path.isfile(args.messages):
    #     print(f'[!] {args.messages} is not a file')
    #     sys.exit(-1)
    #
    # if not os.path.isfile(args.config):
    #     print(f'[!] {args.config} is not a file')
    #     sys.exit(-1)
    # else:
    #     # Read in the config of the clients that will be connecting
    #     with open(args.config, 'r', encoding='utf-8') as config_file:
    #         json_obj = json.load(config_file)
    #         if json_obj:
    #             c_list = json_obj['clients']

    # Accessing/Modifying the OPEN_CONNECTIONS dictionary is not thread_safe so will need to lock access/modifications
    _lock = Lock()
    OPEN_CONNECTIONS = {}
    server_8_bytes = get_random_bytes(8)

    host = get_ip_address()
    port = 8080

    print(f"[!] Server IP {host} & PORT {port}")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(len(c_list))

    print("[!] Server Connection Successful\n")

    # accept clients
    threading_accept = Thread(target=connection_setup, args=[c_list, _lock])
    threading_accept.start()

    # Wait for all clients to connect to the server
    # while len(OPEN_CONNECTIONS.values()) < len(c_list):
    #     time.sleep(1)
    #
    # # We actually do not need to send anything using threading as each client must go before the other so we can just single thread this portion
    # # and handle if a client disconnects
    # with open(args.messages, encoding='utf-8') as messages_file:
    #     csv_reader = csv.reader(messages_file, delimiter=',')
    #     for row in csv_reader:
    #         if row == ['ID', 'Timestamp', 'Contents', 'Attachments', 'UID']:
    #             pass
    #         else:
    #             expected_uid = row[4]
    #             built_message = f'{row[2] + " " if row[2] else ""}{row[3]}'
    #             print(f'[~] SENDING MESSAGE TO {expected_uid} [~] {built_message}')
    #             conn = OPEN_CONNECTIONS.get(row[4])
    #
    #             # Keep trying to send the message until max attempts reached, this gives us a max try of 100 per message
    #             # Should not be hit, but you never know - Will most likely need a way to save session info in case a full rebuild cannot be completed
    #             attempts = 0
    #             while not send_data_frame(conn, built_message, _lock) and attempts < MAX_RETRIES:
    #                 attempts += 1
    #                 # Wait to try an reestablish a connection with all the clients
    #                 while len(OPEN_CONNECTIONS.values()) < len(c_list):
    #                     time.sleep(1)
    #
    # print('[!] Server successfully sent all messages, shutting down\n')
    #
    # for conn in OPEN_CONNECTIONS.values():
    #     print(f'[!] Terminating connection {conn.uid}')
    #     send_data_frame(conn, str(Signal.TERMINATE, 'utf-8'), _lock, wait_for_reply=False)

    # Forces the server to shutdown, it will cause an exception
    # server.close()
    # sys.exit(0)