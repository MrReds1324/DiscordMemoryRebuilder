from utils import build_data_frame, decrypt_data_to_message


# TODO: Update these when encryption has been added
def test_build_data_frame():
    expected_frame = (b'\x00\x00\x00\n', b'0123456789')
    message = b'0123456789'
    built_frame = (build_data_frame(message))
    assert expected_frame == built_frame


def test_decrypt_data_to_message():
    expected_messages = ['0123456789']
    msg_len, msg_data = build_data_frame(b'0123456789')
    read_messages = decrypt_data_to_message(msg_data, None)
    assert expected_messages == read_messages


if __name__ == "__main__":
    test_build_data_frame()
    test_decrypt_data_to_message()
