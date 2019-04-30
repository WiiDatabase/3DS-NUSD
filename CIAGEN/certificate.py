#!/usr/bin/env python3
from Crypto.PublicKey.RSA import construct
from Crypto.Signature import PKCS1_v1_5

from .common import *
from .signature import Signature


class Certificate:
    """Represents a certificate
       Reference: https://www.3dbrew.org/wiki/Certificates

    Args:
        data (bytes, str): Certificate bytes-object or path to file
    """

    class PublicKeyRSA4096(BigEndianStructure):
        _pack_ = 1
        _fields_ = [
            ("modulus", ARRAY(c_byte, 512)),
            ("exponent", c_uint32),
            ("padding", ARRAY(c_byte, 52))
        ]

    class PublicKeyRSA2048(BigEndianStructure):
        _pack_ = 1
        _fields_ = [
            ("modulus", ARRAY(c_byte, 256)),
            ("exponent", c_uint32),
            ("padding", ARRAY(c_byte, 52))
        ]

    class PublicKeyECC(BigEndianStructure):
        _pack_ = 1
        _fields_ = [
            ("key", ARRAY(c_byte, 60)),
            ("padding", ARRAY(c_byte, 60))
        ]

    class Struct(BigEndianStructure):
        _pack_ = 1
        _fields_ = [
            ("issuer", ARRAY(c_byte, 64)),
            ("keyType", c_uint32),
            ("name", ARRAY(c_byte, 64)),
            ("unknown", ARRAY(c_byte, 4))
        ]

        def get_issuer(self):
            return bytes(self.issuer).rstrip(b"\00").decode().split("-")[-1]

        def get_name(self):
            return bytes(self.name).rstrip(b"\00").decode()

        def get_key_type(self):
            """Returns the key type. Reference: https://www.3dbrew.org/wiki/Certificates#Public_Key"""
            key_types = [
                "RSA-4096",
                "RSA-2048",
                "Elliptic Curve"
            ]
            try:
                return key_types[self.keyType]
            except IndexError:
                return "Invalid key type"

        def _do_signer(self, *args):
            if len(self.publicKey) != 0x3C + 0x3C:
                pubkey = construct((int.from_bytes(self.publicKey.modulus, byteorder="big"), self.publicKey.exponent))
                self.signer = PKCS1_v1_5.new(pubkey)
            else:
                self.signer = None

        def __len__(self):
            return sizeof(self.signature) + sizeof(self) + sizeof(self.publicKey)

        def __repr__(self):
            return "{0} issued by {1}".format(self.get_name(), self.get_issuer())

        def __str__(self):
            output = "Certificate:\n"
            output += "  {0} ({1})\n".format(self.get_name(), self.get_key_type())
            output += "  Signed by {0} using {1}".format(self.get_issuer(), repr(self.signature))

            return output

        def pack(self):
            return self.signature.pack() + bytes(self) + self.publicKey.pack()

    def __new__(cls, data):
        if isinstance(data, str):
            with open(str(data), "rb") as fp:
                data = fp.read()
        signature = Signature(data)
        pos = sizeof(signature)
        c_struct = cls.Struct(data[pos:])
        pos += sizeof(c_struct)

        pubkey_length = get_public_key_length(c_struct.keyType)
        if pubkey_length == 0x200 + 0x4 + 0x34:
            c_struct.publicKey = cls.PublicKeyRSA4096(data[pos:])
        elif pubkey_length == 0x100 + 0x4 + 0x34:
            c_struct.publicKey = cls.PublicKeyRSA2048(data[pos:])
        elif pubkey_length == 0x3C + 0x3C:
            c_struct.publicKey = cls.PublicKeyECC(data[pos:])
        else:  # Should never happen because it's handled by get_public_key_length() above
            raise ValueError("Unknown Public Key type")

        c_struct.signature = signature
        c_struct._do_signer()  # TODO: Find a non-hacky way to do this
        return c_struct

    def __init__(self, data):
        pass


class RootKey(BigEndianStructure):
    """Represents the Wii/3DS root-key. Get it here: https://static.hackmii.com/root-key."""
    _pack_ = 1
    _fields_ = [
        ("modulus", ARRAY(c_byte, 512)),
        ("exponent", c_uint32)
    ]

    @staticmethod
    def get_name():
        return "Root"

    @staticmethod
    def get_key_type():
        return "RSA-4096"

    def __init__(self, data):
        pubkey = construct((int.from_bytes(self.modulus, byteorder="big"), self.exponent))
        self.signer = PKCS1_v1_5.new(pubkey)

    def __repr__(self):
        return "3DS Root Certificate"

    def __str__(self):
        output = "Certificate:\n"
        output += "  {0} ({1})\n".format(self.get_name(), self.get_key_type())

        return output
