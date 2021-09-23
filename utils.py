import struct
from typing import List, Tuple
from Crypto.Cipher import AES
from io import BytesIO
from Crypto.PublicKey import RSA
import socket


# from pyautogui import hotkey
# import clipboard
#
# clipboard.copy('test')
#
# spam = clipboard.paste()
# hotkey('ctrl', 'v')
# Leftover code so I dont forget this

class Signal:
    READY = b'~READY~'
    AWAIT = b'~AWAIT~'
    TERMINATE = b'~TERMINATE~'


# Light wrapper around a socket to give a bit more information about the connection and make managing easier
class Connection:
    def __init__(self, uid=None):
        self.socket: socket = None
        self.address: str = ''
        self.port: int = -1
        self.uid: str = uid
        self.encryption_key: AES = None

    def send(self, raw_data: bytes) -> int:
        return self.socket.send(raw_data)

    def receive(self, num_bytes: int) -> bytes:
        return self.socket.recv(num_bytes)

    def close(self):
        self.socket.close()


BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]


# Transmission Overview
# All clients must connect, send their uid, establish a handshake and send a READY signal
# The server will read lines until a new uid is encountered
# The server will then encrypt each message portion, and pack it into a DataFrame
# The server will send one DataFrame at a time and wait to receive the client AWAIT signal for that DataFrame
# The AWAIT signal tells the server to continue onto the next message
# Once all messages have been exhausted, the server will send the TERMINATE signal to all clients


# DataFrames will be constructed with the following
# 4 byte header with the length of the encrypted message followed by the encrypted message
def build_data_frame(encrypted_message: bytes) -> Tuple[bytes, bytes]:
    message_length = len(encrypted_message)
    length_in_bytes = struct.pack('>I', message_length)
    return length_in_bytes, encrypted_message


def decrypt_data_to_message(raw_data: bytes, encryption_key: AES) -> str:
    decrypted_message_data = decrypt_message(raw_data, encryption_key)
    return str(decrypted_message_data, 'utf-8')


# TODO: fill out these utility functions for decrypting/encrypting data
def encrypt_message(raw_message: bytes, encryption_key: AES) -> bytes:
    return raw_message


def decrypt_message(encrypted_data: bytes, encryption_key: AES) -> bytes:
    return encrypted_data
