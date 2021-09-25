import socket
import struct
from typing import Tuple

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class Signal:
    READY = b'~READY~'
    AWAIT = b'~AWAIT~'
    TERMINATE = b'~TERMINATE~'
    RESEND = b'~RESEND~'


# Light wrapper around a socket to give a bit more information about the connection and make managing easier
class Connection:
    def __init__(self, uid=None):
        self.socket: socket = None
        self.address: str = ''
        self.port: int = -1
        self.uid: str = uid
        self.session_key: bytes = b''

    def send(self, raw_data: bytes, flags: int = 0) -> int:
        return self.socket.send(raw_data, flags)

    def receive(self, num_bytes: int, flags: int = 0) -> bytes:
        return self.socket.recv(num_bytes, flags)

    def close(self):
        self.socket.close()

    def sendall(self, raw_data: bytes, flags: int = 0):
        self.socket.sendall(raw_data, flags)


BLOCK_SIZE = 16


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


def decrypt_data_to_message(raw_data: bytes, session_key: bytes) -> str:
    decrypted_message_data = decrypt_message(raw_data, session_key)
    return str(decrypted_message_data, 'utf-8')


def encrypt_data_to_data_frame(raw_data: bytes, encryption_key: AES) -> Tuple[bytes, bytes]:
    encrypted_message = encrypt_message(raw_data, encryption_key)
    return build_data_frame(encrypted_message)


def encrypt_message(raw_message: bytes, session_key: bytes) -> bytes:
    encryption_key = AES.new(session_key, AES.MODE_CBC, session_key[8:] + session_key[:8])
    return encryption_key.encrypt(pad(raw_message, BLOCK_SIZE))


def decrypt_message(encrypted_data: bytes, session_key: bytes) -> bytes:
    encryption_key = AES.new(session_key, AES.MODE_CBC, session_key[8:] + session_key[:8])
    return unpad(encryption_key.decrypt(encrypted_data), BLOCK_SIZE)
