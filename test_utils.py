from utils import build_data_frame, read_data_frames_into_messages


# TODO: Update these when encryption has been added
def test_build_data_frame():
    expected_frame = b'\x00\x00\x00\n0123456789'
    message = b'0123456789'
    built_frame = build_data_frame(message)
    assert expected_frame == built_frame


def test_read_data_frames_into_messages_single():
    expected_messages = ['0123456789']
    built_frame = build_data_frame(b'0123456789')
    read_messages = read_data_frames_into_messages(built_frame, None)
    assert expected_messages == read_messages


def test_read_data_frames_into_messages_multiple():
    expected_messages = ['0123456789', 'This is a message']
    built_frames = build_data_frame(b'0123456789') + build_data_frame(b'This is a message')
    read_messages = read_data_frames_into_messages(built_frames, None)
    assert expected_messages == read_messages


if __name__ == "__main__":
    test_build_data_frame()
    test_read_data_frames_into_messages_single()
    test_read_data_frames_into_messages_multiple()
