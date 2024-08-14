from scapy.all import IP, ICMP, send


ETHERNET_HEADER_SIZE = 14  # 14 bytes * 8 = 112 bits
IPV4_HEADER_SIZE = 20  # 20 bytes * 8 = 160 bits
ICMP_HEADER_SIZE = 8  # 08 bytes * 8 = 64  bits
SEQUENCE_NUMBER_SIZE = 16  # 16 bytes * 8 = 128 bits

MAX_DATA_SIZE = 512  # 512 bytes
PAYLOAD_SIZE = MAX_DATA_SIZE - SEQUENCE_NUMBER_SIZE


class Datagram:
    def __init__(self, sequence_number: int, ip: IP, icmp: ICMP, data: bytes) -> None:
        self.sequence_number = sequence_number
        self.ip = ip
        self.icmp = icmp

        if len(data) > PAYLOAD_SIZE:
            raise ValueError(
                f"Data size ({len(data)} bytes) is bigger than maximum ({PAYLOAD_SIZE} bytes)"
            )

        self.data = self.pack_data(data, sequence_number)

    def calculate_size(self, is_the_last: bool, buffer_size: int) -> int:
        headers_size = (
            ICMP_HEADER_SIZE
            + IPV4_HEADER_SIZE
            + ETHERNET_HEADER_SIZE
            + SEQUENCE_NUMBER_SIZE
        )

        data_size = MAX_DATA_SIZE

        if is_the_last:
            data_size = buffer_size % MAX_DATA_SIZE

        return headers_size + data_size

    def pack_data(self, data: bytes, sequence_number: int) -> bytes:
        sequence_number_bytes = sequence_number.to_bytes(SEQUENCE_NUMBER_SIZE, "big")

        return sequence_number_bytes + data

    def unpack_data(self, data: bytes) -> tuple[bytes, int]:
        sequence_number_bytes = data[0:SEQUENCE_NUMBER_SIZE]
        sequence_number = int.from_bytes(sequence_number_bytes, "big")

        data = data[SEQUENCE_NUMBER_SIZE:]

        return (data, sequence_number)

    def get_bytes(self) -> bytes:
        datagram = self.ip / self.icmp / self.data

        datagram_bytes = bytes(datagram)
        sequence_number_bytes = self.sequence_number.to_bytes(
            SEQUENCE_NUMBER_SIZE, "big"
        )

        return datagram_bytes + sequence_number_bytes

    def send(self) -> None:
        datagram = self.ip / self.icmp / self.data

        send(datagram, verbose=False)


if __name__ == "__main__":
    ip = IP(dst="192.168.56.102")
    icmp = ICMP(type=8, code=0)
    data = b"Sancte Aquine ora pro nobis"

    for i in range(10):
        packet = Datagram(i + 1, ip, icmp, data)
        packet.send()
