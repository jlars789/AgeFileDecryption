from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import base64 as _base64
import math

class AgeFileTestCase:
    password: bytes
    scrypt_salt: bytes
    scrypt_work_factor: int
    wrap_key: bytes

    file_key: bytes
    file_key_encrypted: bytes

    header_mac: bytes
    
    payload_key: bytes
    payload: bytes

    content: bytes

    def generate_header(self) -> bytes:
        header = b"age-encryption.org/v1\n"
        header += b"-> scrypt " + self.scrypt_salt + b" " + str(self.scrypt_work_factor).encode("utf-8") + b"\n"
        header += self.file_key_encrypted + b"\n"
        header += b"---"
        return header


class AgeFile:
    """Class used to represent the contents of an age file.

    :param bytes header: the full header of the file, which should be validated
        against the ``header_hmac`` using HMAC-SHA-256.
    :param bytes scrypt_salt: the salt used by Scrypt when generating the wrap
        key.
    :param bytes scrypt_work_factor: the base-2 log of the work factor used by
        Scrypt when generating the wrap key.
    :param bytes encrypted_file key: the file key, encrypted using
        ChaCha20-Poly1305 using wrap key from the Scrypt stanza.
    :param bytes header_hmac: the HMAC of the file header, which should be
        validated to ensure that the header has not been tampered with.
    :param bytes payload_key_salt: the salt used by HKDF-SHA-256 for the payload
        key.
    :param bytes payload: the age file payload.
    """

    header: bytes
    scrypt_salt: bytes
    scrypt_work_factor: int
    encrypted_file_key: bytes
    header_hmac: bytes
    payload_key_salt: bytes
    payload: bytes

    @property
    def size(self) -> int:
        return len(self.payload)

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.size} bytes)"
        

def b64encode(data: bytes) -> bytes:
    """Base64-encode a string or byte string without padding."""
    data = _base64.b64encode(data)
    return data.replace(b"=", b"")


def b64decode(data: bytes) -> bytes:
    """Base64-decode a byte string without padding."""
    data += b"=" * (-len(data) % 4)
    return _base64.b64decode(data)


def generate_wrap_key(password: bytes, salt: bytes, work_factor: int) -> bytes:
    """Compute the wrap key for an scrypt recipient stanza.
    
    :param bytes password: the password that the wrap key is derived from.
    :param bytes salt: the scrypt salt stored as a Base64-encoded byte string.
    :param int work_factor: the base-two logarithm of the scrypt work factor.
    :return: the stanza's wrap key, which is used to decrypt the file key.
    """

    salt = b"age-encryption.org/v1/scrypt" + b64decode(salt)

    kdf = Scrypt(salt=salt, length=32, n = 2**work_factor, r=8, p=1)
    wrap_key = kdf.derive(password)
    return wrap_key


def decrypt_file_key(
    wrap_key: bytes,
    body: bytes
) -> bytes:
    """Decrypt the file key from an scrypt recipient stanza.
    
    :param bytes wrap_key: the wrap key corresponding to the scrypt recipient
        stanza.
    :param bytes body: the body of the scrypt recipient stanza. This is a Base64-
        encoded byte string that contains the file key (encrypted using
        ChaCha20-Poly1305 with the wrap key.)
    :return: a 16-byte file key for the age file.
    """

    body = b64decode(body)
    nonce = bytes([0]*12)
    chacha = ChaCha20Poly1305(wrap_key)

    return chacha.decrypt(nonce, body, b"")


def generate_payload_key(file_key: bytes, salt: bytes) -> bytes:
    """Generate the age payload key from its file key using HKDF-SHA-256.

    :param bytes file_key: a 16-byte file key.
    :param bytes salt: a salt for HKDF, read from the first 16 bytes of the age
        file payload.
    :return: the 32-byte payload key.
    """

    hkdf = HKDF(algorithm=SHA256(), length=32, salt=salt, info=b"payload")
    return hkdf.derive(file_key)

def generate_hmac_key(file_key: bytes) -> bytes:
    """Generate the key used for the age header HMAC using HKDF-SHA-256.

    :param bytes file_key: the file key.
    :return: returns a 32-byte byte string, computed using HKDF-SHA-256 with an
        empty salt and the info parameter b"header".
    """

    hkdf = HKDF(algorithm=SHA256(), length=32, salt=b"", info=b"header")
    return hkdf.derive(file_key)


def is_valid_header(header: bytes, hmac_key: bytes, mac: bytes) -> bool:
    """Determine whether or not the age file header is valid by checking
    its MAC.

    :param bytes header: the file header, as a byte string.
    :param bytes hmac_key: the key used for HMAC, computed using the
        generate_hmac_key function.
    :param bytes mac: the MAC stored in the header, stored as a Base64-encoded
        byte string.
    :return: return True if the input MAC matches the true MAC.
    """

    mac = b64decode(mac)
    h = HMAC(hmac_key, SHA256())
    h.update(header)
    try:
      h.verify(mac)
      return True
    except:
      return False

# NOTE: we set the chunk size to 65,536 + 16 because the last 16 bytes of each
# chunk are always a Poly1305 tag.
CHUNK_SIZE: int = 64 * 1024 + 16

def decrypt_payload(payload_key: bytes, payload: bytes) -> bytes:
    """Decrypt the payload of an age file.

    :param bytes payload_key: the key for the ChaCha20-Poly1305 cipher used to
        encrypt the payload.
    :param bytes payload: the payload of the age file.
    :return: the decrypted payload as a byte string.
    """
    chacha = ChaCha20Poly1305(payload_key)
    num_chunks = math.floor(len(payload)/CHUNK_SIZE)
    d_payload = b""
    counter = 0
    for i in range(num_chunks):
      nonce = counter.to_bytes(length=11, byteorder="big")
      nonce += b"\x00"
      chunk = payload[i*CHUNK_SIZE:(i+1)*CHUNK_SIZE]
      d_chunk = chacha.decrypt(nonce, chunk, b"")
      d_payload += d_chunk
      counter+=1

    nonce = counter.to_bytes(length=11, byteorder="big")
    nonce += b"\x01"
    fin_chunk = payload[counter*CHUNK_SIZE:]
    d_chunk = chacha.decrypt(nonce, fin_chunk, b"")
    d_payload += d_chunk
    
    return d_payload

def read_age_file(password: bytes, age_file: AgeFile) -> bytes:
    """Read the contents of an age file.

    :param bytes password: the password for the age file.
    :param AgeFile age_file: an ``AgeFile`` instance containing the various
        components of the age file.
    :return: the decrypted payload.
    :raises Exception: if the header is invalid.
    """
    wrap_key = generate_wrap_key(password, age_file.scrypt_salt, age_file.scrypt_work_factor)
    file_key = decrypt_file_key(wrap_key, age_file.encrypted_file_key)
    hmac_key = generate_hmac_key(file_key)
    if not is_valid_header(age_file.header, hmac_key, age_file.header_hmac):
      raise Exception("Header tampered with")
    
    payload_key = generate_payload_key(file_key, age_file.payload_key_salt)
    return decrypt_payload(payload_key, age_file.payload)
