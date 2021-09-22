from enum import Enum


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


# DataFrames will be constructed through the following
# 4 byte header with the length of the encrypted message
# The encrypted message content
# Followed by
def build_data_frame(encrypted_message):
    pass


# TODO: fill out these utility functions for decrypting/encrypting data
def encrypt_message():
    pass


def decrypt_message():
    pass

