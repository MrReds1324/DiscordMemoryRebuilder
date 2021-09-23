import struct
# from pyautogui import hotkey
# import clipboard
#
# clipboard.copy('test')
#
# spam = clipboard.paste()
# hotkey('ctrl', 'v')
# Leftover code so I dont forget this

BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]


# Transmission Overview
# All clients must connect, establish a handshake and send an AWAIT signal
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


# TODO: fill out these utility functions for decrypting/encrypting data
def encrypt_message():
    pass


def decrypt_message():
    pass

