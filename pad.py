PAD_RIGHT = 1
PAD_LEFT = 2


def pad(data: bytes, block_size: int, direction: int) -> bytes:
    data_length = len(data)

    if data_length == block_size:
        return data

    elif data_length < block_size:
        missing = block_size - data_length

    elif data_length > block_size:
        missing = block_size - (data_length % block_size)

    if direction == PAD_RIGHT:
        data = data + b"\0" * missing

    elif direction == PAD_LEFT:
        data = b"\0" * missing + data

    else:
        raise ValueError(f"Invalid argument on direction = {direction}")

    return data
