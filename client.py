import os
import sys
import time
import socket
import struct
import threading
from utils import build_data_frame
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA1
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

from utils import Connection, Signal
from pyautogui import hotkey, press
import clipboard


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
    sha_hash = SHA1.new(rsa_public).digest()
    length, message = build_data_frame(rsa_public + b':' + sha_hash)
    connection.send(length)
    connection.send(message)
    print("[!] Sending RSA and SHA1 to server...")

    length = struct.unpack('>I', connection.receive(4))[0]
    received_bytes = connection.receive(length)
    print(len(received_bytes.split(b':')))
    server_key, server_sha1, encrypted_bytes = received_bytes.split(b':')

    client_sha1 = SHA1.new(server_key).digest()

    if client_sha1 != server_sha1:
        return False

    cipher_rsa = PKCS1_OAEP.new(rsa_private)
    s_8_bytes = cipher_rsa.decrypt(encrypted_bytes)

    server_rsa = RSA.importKey(server_key)
    cipher_rsa = PKCS1_OAEP.new(server_rsa)
    encrypted = cipher_rsa.encrypt(c_8_bytes)

    print(f"[!] Client sending encrypted data: {encrypted}")

    connection.send(encrypted)

    print(f"[!] Server bytes after handshake: {s_8_bytes}")
    print(f"[!] Client bytes after handshake: {c_8_bytes}")

    connection.encryption_key = AES.new(s_8_bytes + c_8_bytes, AES.MODE_CBC, c_8_bytes + s_8_bytes)
    return True


def receive_data_frames(connection: Connection) -> None:
    while True:
        clipboard.copy('test')
        time.sleep(5)

        hotkey('ctrl', 'v')
        press('enter')
        server_signal = Signal.TERMINATE
        if server_signal == Signal.TERMINATE:
            connection.close()
            os._exit(0)  # Not sure if this is safe, but do not know any other way to exit the program


if __name__ == "__main__":
    # Read in stored RSA keys here
    # Otherwise generate new RSA keys here
    key = RSA.generate(2048)
    private_key = key.export_key()
    file_out = open("client_private.pem", "wb")
    file_out.write(private_key)
    file_out.close()

    public_key = key.publickey().export_key()
    file_out = open("client_public.pem", "wb")
    file_out.write(public_key)
    file_out.close()

    client_8_bytes = get_random_bytes(8)
    print(f"[!] Client bytes before handshake: {client_8_bytes}")

    server = Connection('server')
    server.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.address = "127.0.0.1"
    server.port = 8080

    # When we have connected to the server, send the uid and initiate the handshake
    if connect_to_server(server):
        # Manually send the information for the uid over
        server.send(struct.pack('>Q', len(b'test')))
        server.send(b'test')

        if initiate_handshake(server, client_8_bytes, public_key, private_key):
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
