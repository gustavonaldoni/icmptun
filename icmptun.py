from scapy.all import ICMP, IP, send

import aes
import argparse
import datagram
import sys
import textwrap
import threading
import time


SLEEP_SECONDS = 0.1


def print_line():
    print("-" * 40)


def ReLU(number: int) -> int:
    return max(0, number)


class ICMPTunClient:
    def __init__(self, args) -> None:
        self.args = args

    def main_menu(self):
        with open("./interface/main_menu.txt", "r") as main_menu_file:
            print(main_menu_file.read())

    def send(self):
        ip = IP(dst=self.args.target)
        icmp = ICMP(type=8, code=0)
        buffer = b""

        if self.args.file:
            with open(self.args.file, "rb") as file:
                file_data = file.read()
                file_size = len(file_data)

                if self.args.encrypted == "yes":
                    aes_return = aes.aes_encrypt(file_data)
                    buffer = aes_return.pack_bytes()

                elif self.args.encrypted == "no":
                    buffer = file_data

                buffer_size = len(buffer)

                last_block_data_size = buffer_size % datagram.MAX_DATA_SIZE

                sequence_number = 1

                print(f"[*] Initialing:")
                print(f"    - Source IP:            {ip.src}")
                print(f"    - Destination IP:       {ip.dst}")
                print(f"    - Data block size:      {datagram.MAX_DATA_SIZE} bytes")
                print(f"    - Last block data size: {last_block_data_size} bytes")

                if self.args.encrypted == "yes":
                    print(f"    - Encryption:           AES-{aes.AES_KEY_SIZE* 8} EAX")

                print_line()

                print(f"[*] Buffer size:            {buffer_size} bytes")

                if self.args.encrypted == "yes":
                    print(f"    - Key size:             {aes.AES_KEY_SIZE} bytes")
                    print(f"    - Nonce size:           {aes.AES_NONCE_SIZE} bytes")
                    print(f"    - MAC Tag size:         {aes.AES_MAC_TAG_SIZE} bytes")

                print(f"    - File size:            {file_size} bytes")
                print_line()

                packets_to_send = (buffer_size // datagram.MAX_DATA_SIZE) + 1
                packets_size = datagram.calculate_datagram_size(False, buffer_size)
                last_packet_size = datagram.calculate_datagram_size(True, buffer_size)
                time_to_send = SLEEP_SECONDS * packets_to_send

                print(f"[*] Packets to send:        {packets_to_send}")
                print(f"    - Packets size:         {packets_size} bytes")
                print(f"    - Last packet size:     {last_packet_size} bytes")
                print(f"    - Time to send:         {time_to_send} s")
                print_line()

                for i in range(0, buffer_size, datagram.MAX_DATA_SIZE):
                    try:
                        last_chunk = (
                            buffer_size - i == buffer_size % datagram.MAX_DATA_SIZE
                        )

                        if last_chunk:
                            packet = datagram.Datagram(sequence_number, ip, icmp, buffer[i:])
                        else:
                            packet = datagram.Datagram(sequence_number, ip, icmp, buffer[i : i + datagram.MAX_DATA_SIZE])

                        packet.send()

                        remaining = ReLU(buffer_size - (i + datagram.MAX_DATA_SIZE))

                        print(
                            f"[*] Packet {sequence_number} sent.     {remaining} bytes remaining ..."
                        )

                        sequence_number += 1
                        time.sleep(SLEEP_SECONDS)

                    except KeyboardInterrupt:
                        print("Keyboard interruption. Quiting ...")
                        sys.exit()

    def run(self):
        self.main_menu()
        print_line()

        self.send_thread = threading.Thread(target=self.send)
        self.send_thread.start()


class ICMPTunServer:
    def __init__(self, args) -> None:
        self.args = args

    def receive(self):
        pass

    def run(self):
        pass


def main():
    epilog = ""

    with open("./interface/epilog.txt", "r") as epilog_file:
        epilog = epilog_file.read()

    parser = argparse.ArgumentParser(
        description="ICMP Tunneler by Gustavo Naldoni",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(epilog),
    )

    parser.add_argument("-t", "--target", required=True, help="specified IP")
    parser.add_argument("-f", "--file", required=True, help="file to send")
    parser.add_argument(
        "-e",
        "--encrypted",
        required=False,
        default="yes",
        help="use encryption (AES EAX)",
    )

    args = parser.parse_args()

    icmptun = ICMPTunClient(args)
    icmptun.run()


if __name__ == "__main__":
    main()
