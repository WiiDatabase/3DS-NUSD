#!/usr/bin/env python3
import hashlib
import math

from Crypto.Hash import SHA256

try:
    import asyncio
except (ImportError, SyntaxError):
    asyncio = None


class Crypto:
    @classmethod
    def verify_signature(cls, cert, data_to_verify, signature):
        """Returns True if the data is signed by the signer.
           Args:
               cert (Union[Certificate, RootCertificate]): Certificate or Root certificate class
               data_to_verify (bytes): Data that will be verified (data without signature most of the time)
               signature (Signature): Valid Signature class of the data
        """
        return cert.signer.verify(SHA256.new(data_to_verify), signature.signature.data)

    @classmethod
    def create_sha256hash_hex(cls, data):
        return hashlib.sha256(data).hexdigest()

    @classmethod
    def create_sha256hash(cls, data):
        return hashlib.sha256(data).digest()


def align(value, blocksize=64):
    """Aligns value to blocksize

    Args:
        value (int): Length of bytes
        blocksize (int): Block size (Default: 64)

    """
    if value % blocksize != 0:
        return b"\x00" * (64 - (value % 64))
    else:
        return b""


def align_pointer(value, block=64):
    """Aligns pointer to blocksize

    Args:
        value (int): Length of bytes
        block (int): Block size (Default: 64)

    """
    if value % block != 0:
        return block - (value % block)
    else:
        return 0


def read_in_chunks(file_object, chunk_size=1024):
    """Lazy function (generator) to read a file piece by piece.
    Default chunk size: 1k."""
    while True:
        data = file_object.read(chunk_size)
        if not data:
            break
        yield data


def convert_size(size_bytes):
    if size_bytes == 0:
        return "0 B"
    size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return "%s %s" % (s, size_name[i])


def get_sig_size(signature_type):
    # https://www.3dbrew.org/wiki/Title_metadata#Signature_Type
    signature_type = signature_type.hex()
    signature_sizes = {
        # "00010000": 0x200 + 0x3C,
        # "00010001": 0x100 + 0x3C,
        # "00010002": 0x3C + 0x40,
        "00010003": 0x200 + 0x3C,
        "00010004": 0x100 + 0x3C,
        "00010005": 0x3C + 0x40
    }

    try:
        return signature_sizes[signature_type]
    except KeyError:
        raise ValueError("Invalid signature type {0}".format(signature_type))


def get_key_length(key_type):
    # https://www.3dbrew.org/wiki/Certificates#Public_Key
    key_sizes = [
        0x200 + 0x4 + 0x34,
        0x100 + 0x4 + 0x34,
        0x3C + 0x3C
    ]
    try:
        return key_sizes[key_type]
    except IndexError:
        raise ValueError("Invalid key type {0}".format(key_type))


class CachedProperty(object):
    """https://github.com/pydanny/cached-property"""

    def __init__(self, func):
        self.__doc__ = getattr(func, "__doc__")
        self.func = func

    def __get__(self, obj, cls):
        if obj is None:
            return self

        if asyncio and asyncio.iscoroutinefunction(self.func):
            return self._wrap_in_coroutine(obj)

        value = obj.__dict__[self.func.__name__] = self.func(obj)
        return value

    def _wrap_in_coroutine(self, obj):

        @asyncio.coroutine
        def wrapper():
            future = asyncio.ensure_future(self.func(obj))
            obj.__dict__[self.func.__name__] = future
            return future

        return wrapper()
