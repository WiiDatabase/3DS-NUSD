#!/usr/bin/env python3
from ctypes import *

import math


def convert_size(size_bytes):
    """Converts size from integer to a formatted string

    Args:
        size_bytes (int): Size in bytes

    Returns:
        str: Formatted string
    """
    if size_bytes == 0:
        return "0 B"
    size_names = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return "{0} {1}".format(s, size_names[i])


def get_signature_size(signature_type):
    """Determines the length of the signature. Reference: https://www.3dbrew.org/wiki/Title_metadata#Signature_Type

    Args:
        signature_type (bytes): Should be the first four bytes of the signature.

    Returns:
        int: Size of the signature
    """
    signature_type = signature_type.hex()
    signature_sizes = {
        "00010000": 0x200 + 0x3C,
        "00010001": 0x100 + 0x3C,
        "00010002": 0x3C + 0x40,
        "00010003": 0x200 + 0x3C,
        "00010004": 0x100 + 0x3C,
        "00010005": 0x3C + 0x40
    }
    try:
        return signature_sizes[signature_type]
    except KeyError:
        raise ValueError("Invalid signature type {0}".format(signature_type))


def get_public_key_length(key_type):
    """Determines the length of the public key. Reference: https://www.3dbrew.org/wiki/Certificates#Public_Key

    Args:
        key_type (int): The key type.

    Returns:
        int: Size of the public key
    """
    key_sizes = [
        0x200 + 0x4 + 0x34,
        0x100 + 0x4 + 0x34,
        0x3C + 0x3C
    ]
    try:
        return key_sizes[key_type]
    except IndexError:
        raise ValueError("Invalid key type {0}".format(key_type))


class BigEndianStructure(BigEndianStructure):
    def __new__(cls, file=None):
        """Loads file intro Struct if given."""
        if file:
            if isinstance(file, str):
                with open(str(file), "rb") as fp:
                    c_struct = cls.from_buffer_copy(fp.read(sizeof(cls)))
            else:
                c_struct = cls.from_buffer_copy(file)
            return c_struct
        else:
            return super().__new__(cls)

    def __len__(self):
        return sizeof(self)

    def __init__(self, file=None):
        super().__init__()

    def pack(self):
        """Helper function which packs the Struct into a bytes object."""
        return bytes(self)

    def dump(self, filename):
        """Dumps Struct to filename. Returns the filename."""
        with open(str(filename), "wb") as file:
            file.write(self.pack())
            return file.name
