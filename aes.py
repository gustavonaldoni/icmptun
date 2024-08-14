from Crypto.Cipher import AES
from dataclasses import dataclass

import secrets

AES_KEY_SIZE = 32  # 32 bytes * 8 = 256 bits
AES_NONCE_SIZE = 16  # 16 bytes * 8 = 128 bits
AES_MAC_TAG_SIZE = 16  # 16 bytes * 8 = 128 bits


@dataclass
class AESReturnEAXMode:
    key: bytes = b""
    nonce: bytes = b""
    mac_tag: bytes = b""
    ciphertext: bytes = b""

    def pack_bytes(self) -> bytes:
        return self.key + self.nonce + self.mac_tag + self.ciphertext

    def unpack_bytes(self, data: bytes, must_return: bool = False):
        key = data[0:AES_KEY_SIZE]
        nonce = data[AES_KEY_SIZE : AES_KEY_SIZE + AES_NONCE_SIZE]
        mac_tag = data[
            AES_KEY_SIZE
            + AES_NONCE_SIZE : AES_KEY_SIZE
            + AES_NONCE_SIZE
            + AES_MAC_TAG_SIZE
        ]
        ciphertext = data[AES_KEY_SIZE + AES_NONCE_SIZE + AES_MAC_TAG_SIZE :]

        if must_return:
            return AESReturnEAXMode(key, nonce, mac_tag, ciphertext)

        self.key = key
        self.nonce = nonce
        self.mac_tag = mac_tag
        self.ciphertext = ciphertext


def aes_encrypt(data: bytes) -> AESReturnEAXMode:
    key = secrets.token_bytes(AES_KEY_SIZE)
    nonce = secrets.token_bytes(AES_NONCE_SIZE)

    encrypt_cipher = AES.new(key, AES.MODE_EAX, nonce=nonce, mac_len=AES_MAC_TAG_SIZE)
    ciphertext, mac_tag = encrypt_cipher.encrypt_and_digest(data)

    return AESReturnEAXMode(key, nonce, mac_tag, ciphertext)


def aes_decrypt(aes_return: AESReturnEAXMode) -> bytes:
    decrypt_cipher = AES.new(aes_return.key, AES.MODE_EAX, aes_return.nonce)
    plaintext = decrypt_cipher.decrypt_and_verify(
        aes_return.ciphertext, aes_return.mac_tag
    )

    return plaintext
