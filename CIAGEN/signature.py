#!/usr/bin/env python3
from .common import *


class Signature:
    """Represents the Signature
       Reference: https://www.3dbrew.org/wiki/Title_metadata#Signature_Data

    Args:
        data (bytes): 3DS Signature
    """

    class RSA4096(BigEndianStructure):
        _pack_ = 1
        _fields_ = [
            ("type", c_uint32),
            ("data", ARRAY(c_byte, 0x200)),
            ("padding", ARRAY(c_byte, 0x3C))
        ]

        def __repr__(self):
            return "RSA-4096"

    class RSA2048(BigEndianStructure):
        _pack_ = 1
        _fields_ = [
            ("type", c_uint32),
            ("data", ARRAY(c_byte, 0x100)),
            ("padding", ARRAY(c_byte, 0x3C))
        ]

        def __repr__(self):
            return "RSA-2048"

    class ECC(BigEndianStructure):
        _pack_ = 1
        _fields_ = [
            ("type", c_uint32),
            ("data", ARRAY(c_byte, 0x3C)),
            ("padding", ARRAY(c_byte, 0x40))
        ]

        def __repr__(self):
            return "ECC/ECDSA"

    def __new__(cls, data):
        """Modified __new__ which determines the signature size."""
        signature_length = get_signature_size(data[:4])
        if signature_length == 572:  # RSA-4096
            signature = cls.RSA4096(data)
        elif signature_length == 316:  # RSA-2048
            signature = cls.RSA2048(data)
        elif signature_length == 124:  # ECC
            signature = cls.ECC(data)
        else:  # Should never happen because it's handled by get_signature_size() above
            raise ValueError("Unknown signature type with length {0}".format(signature_length))
        return signature

    def __init__(self, data):
        pass
