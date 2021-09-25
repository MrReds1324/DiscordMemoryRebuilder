import argparse
import os
import random
import socket
import struct
import sys
import time
from threading import Thread

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA1
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from pyautogui import write, press

from utils import Connection, Signal, decrypt_message, encrypt_data_to_data_frame
from utils import build_data_frame


def connect_to_server(connection: Connection, max_attempts: int = 5) -> bool:
    attempts = 0
    while attempts < max_attempts:
        try:
            attempts += 1
            connection.socket.connect((connection.address, connection.port))
            print("[!] Connection Successful")
            return True
        except Exception as e:
            print(f"[!] Attempts remaining: {max_attempts - attempts} {e}")
            time.sleep(1)

    return False


def initiate_handshake(connection: Connection, c_8_bytes: bytes, rsa_public: RSA, rsa_private: RSA) -> bool:
    try:
        client_sha1 = SHA1.new(rsa_public).digest()
        length, message = build_data_frame(rsa_public + client_sha1)
        connection.send(length)
        connection.send(message)
        print("[!] Sending RSA and SHA1 to server...")

        length = struct.unpack('>I', connection.receive(4))[0]
        received_bytes = connection.receive(length)
        server_key = received_bytes[:-20]
        server_sha1 = received_bytes[-20:]

        length = struct.unpack('>I', connection.receive(4))[0]
        encrypted_bytes = connection.receive(length)

        if client_sha1 != server_sha1:
            return False

        private_rsa_key = RSA.importKey(rsa_private)
        cipher_rsa = PKCS1_OAEP.new(private_rsa_key)
        s_8_bytes = cipher_rsa.decrypt(encrypted_bytes)

        server_rsa = RSA.importKey(server_key)
        cipher_rsa = PKCS1_OAEP.new(server_rsa)
        encrypted = cipher_rsa.encrypt(c_8_bytes)

        connection.send(struct.pack('>I', len(encrypted)))
        connection.send(encrypted)

        connection.session_key = s_8_bytes + c_8_bytes
        return True
    except ConnectionResetError:
        return False


def receive_data_frames(connection: Connection) -> None:
    # Start a short delay before receiving data to allow for tabbing into a server/channel
    time_to_start = 10
    for i in range(2):
        print(f'[!] Starting receiving data frames in {time_to_start} seconds')
        time.sleep(5)
        time_to_start -= 5

    print('[!] Receiving data frames')
    while True:
        try:
            message_len_bytes = connection.receive(4)
            message_len = struct.unpack('>I', message_len_bytes)[0]
            message_bytes = connection.receive(message_len)

            decrypted_message_bytes = decrypt_message(message_bytes, connection.session_key)

            # If the decrypted message is the terminate signal, stop the client
            if decrypted_message_bytes == Signal.TERMINATE:
                connection.close()  # Not sure if this is safe, but do not know any other way to exit the program
                os._exit(0)

            message = str(decrypted_message_bytes, 'utf-8')
            print(f'[~] RECEIVED MESSAGE [~] {message}')

            # Write the message out to wherever the user is tabbed into
            write(message)
            press('enter')
            time.sleep(random.uniform(0, 1))

            data_length, encrypted_message = encrypt_data_to_data_frame(Signal.AWAIT, connection.session_key)
            connection.send(data_length)
            connection.send(encrypted_message)
        except ConnectionResetError:  # Handle connection reset, and attempt to reestablish connection to the server
            connection.close()
            server.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if connect_to_server(connection, 500):

                # Manually send the information for the uid over
                uid_bytes = bytes(connection.uid, 'utf-8')
                connection.send(struct.pack('>Q', len(uid_bytes)))
                connection.send(uid_bytes)

                if initiate_handshake(connection, client_8_bytes, public_key, private_key):
                    connection.send(Signal.READY)
                else:
                    print('[!] Failed to properly exchange key information with the server')
                    connection.close()
                    os._exit(-1) # Not sure if this is safe, but do not know any other way to exit the program

        except Exception as e:
            print(f'[!] Something went wrong when receiving the data frame: {e}')
            data_length, encrypted_message = encrypt_data_to_data_frame(Signal.RESEND, connection.session_key)
            connection.send(data_length)
            connection.send(encrypted_message)


if __name__ == "__main__":
    # Generate RSA public/private keys
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    parser = argparse.ArgumentParser(description='Pass in a uid to register yourself to the server with, and receive those messages')
    parser.add_argument('-uid', '--unique-id', type=str, required=True, help='The unique id to register to the server with, and receive the messages of')
    # parser.add_argument('-ip', '--ip-address', type=str, required=True, help='The IP of the server to connect to')

    args = parser.parse_args()

    client_8_bytes = get_random_bytes(8)

    server = Connection(args.unique_id)
    server.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.address = "127.0.0.1"
    server.port = 8080

    # When we have connected to the server, send the uid and initiate the handshake
    if connect_to_server(server):
        # Manually send the information for the uid over
        uid_bytes = bytes(server.uid, 'utf-8')
        server.send(struct.pack('>Q', len(uid_bytes)))
        server.send(uid_bytes)

        if initiate_handshake(server, client_8_bytes, public_key, private_key):
            server.send(Signal.READY)
        else:
            print('[!] Failed to properly exchange key information with the server')
            server.close()
            sys.exit(-1)

        threading_receive_data = Thread(target=receive_data_frames, args=[server])
        threading_receive_data.start()

