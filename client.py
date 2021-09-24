import os
import sys
import time
import socket
import struct
import threading
import hashlib
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from utils import Connection, Signal
from pyautogui import write, press


def connect_to_server(connection: Connection) -> bool:
    attempts = 0
    while attempts < 5:
        try:
            attempts += 1
            connection.socket.connect((connection.address, connection.port))
            print("[!] Connection Successful")
            return True
        except:
            print(f"[!] Attempts remaining: {5 - attempts}")

    return False


def initiate_handshake(connection: Connection, c_8_bytes: bytes, rsa_public: RSA, rsa_private: RSA) -> bool:
    return True


def receive_data_frames(connection: Connection) -> None:
    print('Waiting for data frames')
    while True:
        time.sleep(5)

        write('test')
        press('enter')
        server_signal = Signal.TERMINATE
        if server_signal == Signal.TERMINATE:
            connection.close()
            os._exit(0)  # Not sure if this is safe, but do not know any other way to exit the program


if __name__ == "__main__":
    # Read in stored RSA keys here
    # with open('client_private.pem', 'rb'):
    #     pass
    # with open('client_public.pem', 'rb'):
    #     pass
    # Otherwise generate new RSA keys here

    client_8_bytes = get_random_bytes(8)

    server = Connection('server')
    server.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.address = "127.0.0.1"
    server.port = 8080

    # When we have connected to the server, send the uid and initiate the handshake
    if connect_to_server(server):
        # Manually send the information for the uid over
        server.send(struct.pack('>Q', len(b'test')))
        server.send(b'test')

        if initiate_handshake(server, client_8_bytes, None, None):
            server.send(Signal.READY)
        else:
            print(f"[!] Failed to properly exchange key information with the server")
            sys.exit(-1)

        threading_receive_data = threading.Thread(target=receive_data_frames, args=[server])
        threading_receive_data.start()

    # This keeps the client program going while we wait for data frames to be sent
    # and allows us to keyboard interrupt it if necessary
    while True:
        pass
