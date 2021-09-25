from utils import build_data_frame, decrypt_data_to_message, encrypt_message, decrypt_message

session_key = b'1234123412341235'


# TODO: Update these when encryption has been added
def test_build_data_frame():
    expected_frame = (b'\x00\x00\x00\n', b'0123456789')
    message = b'0123456789'
    built_frame = (build_data_frame(message))
    assert expected_frame == built_frame


def test_encrypt_and_decrypt_message():
    expected_ciphertext = b'5^\xf03\xf0\xe0\xcf\xf2\xc5-\x86\xaf\x05\xeb\xe9\x03'
    message_to_encryt = b'message'
    encrypted = encrypt_message(message_to_encryt, session_key)
    assert encrypted == expected_ciphertext

    decrypted = decrypt_message(encrypted, session_key)
    assert decrypted == message_to_encryt


def test_decrypt_data_to_message():
    expected_messages = 'message'
    encrypted_ciphertext = b'5^\xf03\xf0\xe0\xcf\xf2\xc5-\x86\xaf\x05\xeb\xe9\x03'
    msg_len, msg_data = build_data_frame(encrypted_ciphertext)
    read_messages = decrypt_data_to_message(msg_data, session_key)
    assert expected_messages == read_messages


if __name__ == "__main__":
    test_build_data_frame()
    test_encrypt_and_decrypt_message()
    test_decrypt_data_to_message()
