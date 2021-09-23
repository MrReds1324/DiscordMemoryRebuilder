import struct
from typing import List
from Crypto.Cipher import AES
from io import BytesIO


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
    END = b'~END~'
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


BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]


# Transmission Overview
# All clients must connect, send their uid, establish a handshake and send an READY signal
# The server will read lines until a new uid is encountered
# The server will then encrypt each message portion, and pack it into a DataFrame
# The server will send all DataFrames for the client to read and decrypt
# The server will signal that all DataFrames have been sent by terminating the stream with an END signal
# Once the client has successfully "used" all messages, it will send an AWAIT signal back to the server
# The AWAIT signal tells the server to continue onto the next set of messages
# Once all messages have been exhausted, the server will send the TERMINATE signal


# DataFrames will be constructed with the following
# 4 byte header with the length of the encrypted message followed by the encrypted message
def build_data_frame(encrypted_message: bytes) -> bytes:
    message_length = len(encrypted_message)
    length_in_bytes = struct.pack('>I', message_length)
    return length_in_bytes + encrypted_message


def read_data_frames_into_messages(raw_data: bytes, encryption_key: AES) -> List[str]:
    message_list = []
    # Transform our bytes into a byte stream which will allow us to much more easily read the data
    data_stream = BytesIO(raw_data)

    while True:
        message_length_bytes = data_stream.read(4)
        if message_length_bytes == b'':  # Break when we read the end of the stream
            break

        message_length = struct.unpack('>I', message_length_bytes)[0]
        encrypted_message_data = data_stream.read(message_length)
        decrypted_message_data = decrypt_message(encrypted_message_data, encryption_key)

        message = str(decrypted_message_data, 'utf-8')
        message_list.append(message)

    return message_list


# TODO: fill out these utility functions for decrypting/encrypting data
def encrypt_message(raw_message: bytes, encryption_key: AES) -> bytes:
    return raw_message


def decrypt_message(encrypted_data: bytes, encryption_key: AES) -> bytes:
    return encrypted_data
