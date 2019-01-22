#!/usr/bin/env python3
import binascii
import os
import struct

from Crypto.PublicKey.RSA import construct
from Crypto.Signature import PKCS1_v1_5
from requests import get, HTTPError

import utils
from Struct import Struct
from utils import CachedProperty


class Signature:
    """Represents the Signature
       Reference: https://www.3dbrew.org/wiki/Title_metadata#Signature_Data
    """

    class SignatureRSA2048SHA256(Struct):
        __endian__ = Struct.BE

        def __format__(self):
            self.type = Struct.uint32
            self.data = Struct.string(0x100)
            self.padding = Struct.string(0x3C)

    class SignatureRSA4096SHA256(Struct):
        __endian__ = Struct.BE

        def __format__(self):
            self.type = Struct.uint32
            self.data = Struct.string(0x200)
            self.padding = Struct.string(0x3C)

    class SignatureECDSASHA256(Struct):
        __endian__ = Struct.BE

        def __format__(self):
            self.type = Struct.uint32
            self.data = Struct.string(0x3C)
            self.padding = Struct.string(0x40)

    def __init__(self, filebytes):
        signature_type = filebytes[:4]
        self.signature_length = utils.get_sig_size(signature_type)
        if self.signature_length == 0x200 + 0x3C:
            self.signature = self.SignatureRSA4096SHA256()
        elif self.signature_length == 0x100 + 0x3C:
            self.signature = self.SignatureRSA2048SHA256()
        elif self.signature_length == 0x3C + 0x40:
            self.signature = self.SignatureECDSASHA256()
        else:
            raise Exception("Unknown signature type {0}".format(signature_type))  # Should never happen
        self.signature = self.signature.unpack(filebytes[:0x04 + self.signature_length])

    def __len__(self):
        return 0x04 + self.signature_length

    def __repr__(self):
        return "{0} Signature Data".format(self.get_signature_type())

    def pack(self):
        return self.signature.pack()

    def get_signature_type(self):
        if self.signature_length == 0x200 + 0x3C:
            return "RSA-4096 SHA256"
        elif self.signature_length == 0x100 + 0x3C:
            return "RSA-2048 SHA256"
        elif self.signature_length == 0x3C + 0x40:
            return "ECDSA SHA256"
        else:
            return "Unknown"


class Certificate:
    """Represents a Certificate
       Reference: https://www.3dbrew.org/wiki/Certificates
    """

    class CertificateStruct(Struct):
        __endian__ = Struct.BE

        def __format__(self):
            self.issuer = Struct.string(0x40)
            self.key_type = Struct.uint32
            self.name = Struct.string(0x40)
            self.unknown = Struct.uint32

    class PubKeyRSA4096(Struct):
        __endian__ = Struct.BE

        def __format__(self):
            self.modulus = Struct.string(0x200)
            self.exponent = Struct.uint32
            self.padding = Struct.string(0x34)

    class PubKeyRSA2048(Struct):
        __endian__ = Struct.BE

        def __format__(self):
            self.modulus = Struct.string(0x100)
            self.exponent = Struct.uint32
            self.padding = Struct.string(0x34)

    class PubKeyECC(Struct):
        __endian__ = Struct.BE

        def __format__(self):
            self.key = Struct.string(0x3C)
            self.padding = Struct.string(0x3C)

    def __init__(self, filebytes):
        self.signature = Signature(filebytes)
        self.certificate = self.CertificateStruct().unpack(
            filebytes[len(self.signature):
                      len(self.signature) + len(self.CertificateStruct())]
        )
        pubkey_length = utils.get_key_length(self.certificate.key_type)
        if pubkey_length == 0x200 + 0x4 + 0x34:
            self.pubkey_struct = self.PubKeyRSA4096()
        elif pubkey_length == 0x100 + 0x4 + 0x34:
            self.pubkey_struct = self.PubKeyRSA2048()
        elif pubkey_length == 0x3C + 0x3C:
            self.pubkey_struct = self.PubKeyECC()
        else:
            raise Exception("Unknown Public Key type")  # Should never happen
        self.pubkey_struct = self.pubkey_struct.unpack(
            filebytes[len(self.signature) + len(self.certificate):
                      len(self.signature) + len(self.certificate) + pubkey_length]
        )
        if pubkey_length != 0x3C + 0x3C:
            self.pubkey = construct(
                (int.from_bytes(self.pubkey_struct.modulus, byteorder="big"), self.pubkey_struct.exponent)
            )
            self.signer = PKCS1_v1_5.new(self.pubkey)
        else:
            self.pubkey = None
            self.signer = None

    def __len__(self):
        return len(self.signature) + len(self.certificate) + len(self.pubkey_struct)

    def __repr__(self):
        return "{0} issued by {1}".format(self.get_name(), self.get_issuer())

    def __str__(self):
        output = "Certificate:\n"
        output += "  {0} ({1})\n".format(self.get_name(), self.get_key_type())
        output += "  Signed by {0} using {1}".format(self.get_issuer(), self.signature.get_signature_type())

        return output

    def pack(self):
        return self.signature.pack() + self.signature_pack()

    def signature_pack(self):
        return self.certificate.pack() + self.pubkey_struct.pack()

    def get_issuer(self):
        return self.certificate.issuer.rstrip(b"\00").decode().split("-")[-1]

    def get_name(self):
        return self.certificate.name.rstrip(b"\00").decode()

    def get_key_type(self):
        # https://www.3dbrew.org/wiki/Certificates#Public_Key
        key_types = [
            "RSA-4096",
            "RSA-2048",
            "Elliptic Curve"
        ]
        try:
            return key_types[self.certificate.key_type]
        except IndexError:
            return "Invalid key type"


class RootCertificate:
    """Represents the Root Certificate
       Reference: https://www.3dbrew.org/wiki/Certificates
    """

    class PubKeyRSA4096(Struct):
        __endian__ = Struct.BE

        def __format__(self):
            self.modulus = Struct.string(0x200)
            self.exponent = Struct.uint32

    def __init__(self, file):
        if isinstance(file, str):  # Load file
            try:
                file = open(file, 'rb').read()
            except FileNotFoundError:
                raise FileNotFoundError('File not found')
        self.pubkey_struct = self.PubKeyRSA4096().unpack(file)
        self.pubkey = construct(
            (int.from_bytes(self.pubkey_struct.modulus, byteorder="big"), self.pubkey_struct.exponent)
        )
        self.signer = PKCS1_v1_5.new(self.pubkey)

    def __len__(self):
        return len(self.pubkey_struct)

    def __repr__(self):
        return "3DS Root Certificate"

    def __str__(self):
        output = "Certificate:\n"
        output += "  {0} ({1})\n".format(self.get_name(), self.get_key_type())

        return output

    def pack(self):
        return self.pubkey_struct.pack()

    @staticmethod
    def get_name():
        return "Root"

    @staticmethod
    def get_key_type():
        return "RSA-4096"


if os.path.isfile("root-key"):
    ROOT_KEY = RootCertificate("root-key")  # https://static.hackmii.com/root-key
else:
    ROOT_KEY = None


class TMD:
    """Represents the Title Metadata
       Reference: https://www.3dbrew.org/wiki/Title_metadata

    Args:
        file (Union[str, bytes]): Path to TMD or a TMD bytes-object
    """

    class TMDHeader(Struct):
        __endian__ = Struct.BE

        def __format__(self):
            self.issuer = Struct.string(0x40)
            self.version = Struct.uint8
            self.ca_crl_version = Struct.uint8
            self.signer_crl_version = Struct.uint8
            self.reserved1 = Struct.uint8
            self.system_version = Struct.uint64
            self.titleid = Struct.uint64
            self.type = Struct.uint32
            self.group_id = Struct.uint16
            self.savedata_size = Struct.uint32
            self.srl_private_data_size = Struct.uint32
            self.reserved2 = Struct.uint32
            self.srl_flag = Struct.uint8
            self.reserved3 = Struct.string(0x31)
            self.access_rights = Struct.uint32
            self.titleversion = Struct.uint16
            self.contentcount = Struct.uint16
            self.bootcontent = Struct.uint16
            self.padding = Struct.string(2)
            self.sha256 = Struct.string(0x20)

    class TMDContentInfoRecords(Struct):
        __endian__ = Struct.BE

        def __format__(self):
            self.cid_offset = Struct.uint16
            self.ccc = Struct.uint16
            self.sha256 = Struct.string(0x20)

    class TMDContents(Struct):
        __endian__ = Struct.BE

        def __format__(self):
            self.cid = Struct.uint32
            self.index = Struct.uint16
            self.type = Struct.uint16
            self.size = Struct.uint64
            self.sha256 = Struct.string(0x20)

        def get_cid(self):
            return ("%08X" % self.cid).lower()

        def get_type(self):
            # https://www.3dbrew.org/wiki/Title_metadata#Content_Index
            # TODO: DLC?
            types = [
                "Main",
                "System/Manual",
                "DLP"
            ]
            try:
                return types[self.index]
            except KeyError:
                return "Unknown"

        def __repr__(self):
            output = "Content {0} ({1})".format(self.get_cid(), self.get_type())
            return output

        def __str__(self):
            output = "Content:\n"
            output += "   ID         Index   Type           Size       Hash\n"
            output += "   {:08X}   {:<7d} {:<14s} {:<11s}".format(
                self.cid,
                self.index,
                self.get_type(),
                utils.convert_size(self.size)
            )
            output += binascii.hexlify(self.sha256).decode() + "\n"

            return output

    def __init__(self, file):
        if isinstance(file, str):  # Load file
            try:
                file = open(file, 'rb').read()
            except FileNotFoundError:
                raise FileNotFoundError('File not found')

        # Signature
        self.signature = Signature(file)
        pos = len(self.signature)

        # Header
        self.hdr = self.TMDHeader().unpack(file[pos:pos + 0xC4])
        pos += len(self.hdr)

        # Content Info Records
        self.content_info = []
        for i in range(64):
            self.content_info.append(self.TMDContentInfoRecords().unpack(file[pos:pos + 0x24]))
            pos += 0x24

        # Content Chunk Records
        self.contents = []
        for i in range(self.hdr.contentcount):
            self.contents.append(self.TMDContents().unpack(file[pos:pos + 0x30]))
            pos += 0x30

        # Certificates
        self.certificates = []
        if file[pos:]:
            self.certificates.append(Certificate(file[pos:]))
            pos += len(self.certificates[0])
            self.certificates.append(Certificate(file[pos:]))

    def get_titleid(self):
        return "{:08X}".format(self.hdr.titleid).zfill(16).lower()

    def get_content_size(self):
        size = 0
        for content in self.contents:
            size += content.size
        return size

    def pack(self):
        """Returns TMD WITHOUT certificates."""
        pack = self.signature.pack() + self.signature_pack()
        for content_info in self.content_info:
            pack += content_info.pack()
        for content in self.contents:
            pack += content.pack()
        return pack

    def signature_pack(self):
        """Returns TMD only with header (the part that is signed)."""
        pack = self.hdr.pack()

        return pack

    def dump(self, output=None):
        """Dumps TMD to output WITH Certificates. Replaces {titleid} and {titleversion} if in filename.
           Returns raw binary if no output is given, returns the file path else.
        """
        if output:
            output = output.format(titleid=self.get_titleid(), titleversion=self.hdr.titleversion)
        pack = self.pack()
        for cert in self.certificates:
            pack += cert.pack()
        if output:
            with open(output, "wb") as tmd_file:
                tmd_file.write(pack)
                return output
        else:
            return pack

    def get_issuer(self):
        """Returns list with the certificate chain issuers.
           There should be exactly three: the last one (CP) signs the TMD,
           the one before that (CA) signs the CP cert and
           the first one (Root) signs the CA cert.
        """
        return self.hdr.issuer.rstrip(b"\00").decode().split("-")

    def get_cert_by_name(self, name):
        """Returns certificate by name."""
        for i, cert in enumerate(self.certificates):
            if cert.get_name() == name:
                return i
        if name == "Root":
            if ROOT_KEY:
                return ROOT_KEY
        raise ValueError("Certificate '{0}' not found.".format(name))

    def __len__(self):
        """Returns length of TMD WITHOUT certificates."""
        size = 0
        for content_info in self.content_info:
            size += len(content_info)
        for content in self.contents:
            size += len(content)
        return size + len(self.signature) + len(self.hdr)

    def __repr__(self):
        return 'Title {id} v{ver}'.format(
            id=self.get_titleid(),
            ver=self.hdr.titleversion,
        )

    def __str__(self):
        output = "TMD:\n"
        output += "  Title ID: {0}\n".format(self.get_titleid())
        output += "  Title Version: {0}\n".format(self.hdr.titleversion)
        output += "\n"
        output += "  Number of contents: {0}\n".format(self.hdr.contentcount)
        output += "  Contents:\n"
        output += "   ID         Index   Type           Size       Hash\n"
        for content in self.contents:
            output += "   {:08X}   {:<7d} {:<14s} {:<11s}".format(
                content.cid,
                content.index,
                content.get_type(),
                utils.convert_size(content.size)
            )
            output += binascii.hexlify(content.sha256).decode() + "\n"

        # TODO: Improve this, is a bit complicated to understand and duplicated
        if self.certificates:
            output += "\n"
            output += "  Certificates:\n"
            try:
                signs_tmd = self.get_cert_by_name(self.get_issuer()[-1])  # CP
                signs_cp = self.get_cert_by_name(self.get_issuer()[1])  # CA
            except ValueError:
                output += "   Could not locate the needed certificates.\n"
                return output
            try:
                signs_ca = self.get_cert_by_name(self.get_issuer()[0])  # Root
            except ValueError:
                signs_ca = None

            # Check TMD signature
            verified = utils.Crypto.verify_signature(
                self.certificates[signs_tmd],
                self.signature_pack(),
                self.signature
            )
            sha256hash = utils.Crypto.create_sha256hash_hex(self.signature_pack())
            output += "    TMD signed by {0} using {1}:\n      {2} ".format(
                "-".join(self.get_issuer()),
                self.certificates[signs_tmd].get_key_type(),
                sha256hash
            )
            if verified:
                output += "[OK]"
            else:
                output += "[FAIL]"
            output += "\n"

            # Check CP signature
            verified = utils.Crypto.verify_signature(
                self.certificates[signs_cp],
                self.certificates[signs_tmd].signature_pack(),
                self.certificates[signs_tmd].signature
            )
            sha256hash = utils.Crypto.create_sha256hash_hex(self.certificates[signs_tmd].signature_pack())
            output += "    {0} ({1}) signed by {2} ({3}):\n      {4} ".format(
                self.certificates[signs_tmd].get_name(),
                self.certificates[signs_tmd].get_key_type(),
                self.certificates[signs_tmd].get_issuer(),
                self.certificates[signs_cp].get_key_type(),
                sha256hash
            )
            if verified:
                output += "[OK]"
            else:
                output += "[FAIL]"
            output += "\n"

            # Check Root signature
            if signs_ca:
                verified = utils.Crypto.verify_signature(
                    signs_ca,
                    self.certificates[signs_cp].signature_pack(),
                    self.certificates[signs_cp].signature
                )
                sha256hash = utils.Crypto.create_sha256hash_hex(self.certificates[signs_cp].signature_pack())
                output += "    {0} ({1}) signed by {2} ({3}):\n      {4} ".format(
                    self.certificates[signs_cp].get_name(),
                    self.certificates[signs_cp].get_key_type(),
                    self.certificates[signs_cp].get_issuer(),
                    ROOT_KEY.get_key_type(),
                    sha256hash
                )
                if verified:
                    output += "[OK]"
                else:
                    output += "[FAIL]"
            else:
                output += "    {0} ({1}) signed by {2}: Please place root-key in the same directory".format(
                    self.certificates[signs_cp].get_name(),
                    self.certificates[signs_cp].get_key_type(),
                    self.certificates[signs_cp].get_issuer()
                )
            output += "\n"

        return output


class Ticket:
    """Represents the Ticket
       Reference: https://www.3dbrew.org/wiki/Ticket

    Args:
        file (Union[str, bytes]): Path to Ticket or a Ticket bytes-object
    """

    class TicketHeader(Struct):
        __endian__ = Struct.BE

        def __format__(self):
            self.issuer = Struct.string(0x40)
            self.eccpubkey = Struct.string(0x3C)
            self.version = Struct.uint8
            self.ca_crl_version = Struct.uint8
            self.signer_crl_version = Struct.uint8
            self.titlekey = Struct.string(0x10)
            self.reserved1 = Struct.uint8
            self.ticketid = Struct.uint64
            self.consoleid = Struct.uint32
            self.titleid = Struct.uint64
            self.reserved2 = Struct.uint16
            self.titleversion = Struct.uint16
            self.reserved3 = Struct.uint64
            self.license_type = Struct.uint8
            self.ckeyindex = Struct.uint8
            self.reserved4 = Struct.string(0x2A)
            self.eshopid = Struct.uint32
            self.reserved5 = Struct.uint8
            self.audit = Struct.uint8
            self.reserved6 = Struct.string(0x42)
            self.demo = Struct.uint32
            self.maxplaycount = Struct.uint32
            self.limits = Struct.string(0x38)
            self.cindex = Struct.string(0xAC)

    def __init__(self, file):
        if isinstance(file, str):
            try:
                file = open(file, 'rb').read()
            except FileNotFoundError:
                raise FileNotFoundError('File not found')

        # Signature
        self.signature = Signature(file)
        pos = len(self.signature)

        # Header
        self.hdr = self.TicketHeader().unpack(file[pos:pos + 0x210])
        pos += len(self.hdr)
        self.titleiv = struct.pack(">Q", self.hdr.titleid) + b"\x00" * 8

        # Certificates
        self.certificates = []
        if file[pos:]:
            self.certificates.append(Certificate(file[pos:]))
            pos += len(self.certificates[0])
            self.certificates.append(Certificate(file[pos:]))

    def get_titleid(self):
        return "{:08X}".format(self.hdr.titleid).zfill(16).lower()

    def get_issuer(self):
        """Returns list with the certificate chain issuers.
           There should be exactly three: the last one (XS) signs the Ticket,
           the one before that (CA) signs the CP cert and
           the first one (Root) signs the CA cert.
        """
        return self.hdr.issuer.rstrip(b"\00").decode().split("-")

    def get_cert_by_name(self, name):
        """Returns certificate by name."""
        for i, cert in enumerate(self.certificates):
            if cert.get_name() == name:
                return i
        if name == "Root":
            if ROOT_KEY:
                return ROOT_KEY
        raise ValueError("Certificate '{0}' not found.".format(name))

    def pack(self):
        """Returns ticket WITHOUT certificates"""
        return self.signature.pack() + self.hdr.pack()

    def signature_pack(self):
        """Returns Ticket only with body (the part that is signed)."""
        return self.hdr.pack()

    def dump(self, output=None):
        """Dumps ticket to output WITH Certificates. Replaces {titleid} and {titleversion} if in filename.
           NOTE that the titleversion in the ticket is often wrong!
           Returns raw binary if no output is given, returns the file path else.
        """
        if output:
            output = output.format(titleid=self.get_titleid(), titleversion=self.hdr.titleversion)
        pack = self.pack()
        for cert in self.certificates:
            pack += cert.pack()
        if output:
            with open(output, "wb") as cetk_file:
                cetk_file.write(pack)
                return output
        else:
            return pack

    def __len__(self):
        """Returns length of ticket WITHOUT certificates"""
        return len(self.signature) + len(self.hdr)

    def __repr__(self):
        return 'Ticket for title {id} v{ver}'.format(id=self.get_titleid(), ver=self.hdr.titleversion)

    def __str__(self):
        output = "Ticket:\n"
        output += "  Title ID: {0}\n".format(self.get_titleid())
        output += "  Ticket Title Version: {0}\n".format(self.hdr.titleversion)
        if self.hdr.consoleid:
            output += "  Console ID: {0}\n".format(self.hdr.consoleid)
        output += "\n"
        output += "  Initialization vector: {0}\n".format(binascii.hexlify(self.titleiv).decode())
        output += "  Title key (encrypted): {0}\n".format(binascii.hexlify(self.hdr.titlekey).decode())
        if self.hdr.demo == 4:
            output += "  Demo limit active - Max playcount: {0}\n".format(self.hdr.maxplaycount)

        # TODO: Improve this, is a bit complicated to understand and duplicated
        if self.certificates:
            output += "\n"
            output += "  Certificates:\n"
            try:
                signs_ticket = self.get_cert_by_name(self.get_issuer()[-1])  # XS
                signs_cp = self.get_cert_by_name(self.get_issuer()[1])  # CA
            except ValueError:
                output += "   Could not locate the needed certificates.\n"
                return output
            try:
                signs_ca = self.get_cert_by_name(self.get_issuer()[0])  # Root
            except ValueError:
                signs_ca = None

            # Check Ticket signature
            verified = utils.Crypto.verify_signature(
                self.certificates[signs_ticket],
                self.signature_pack(),
                self.signature
            )
            sha256hash = utils.Crypto.create_sha256hash_hex(self.signature_pack())
            output += "    Ticket signed by {0} using {1}:\n      {2} ".format(
                "-".join(self.get_issuer()),
                self.certificates[signs_ticket].get_key_type(),
                sha256hash
            )
            if verified:
                output += "[OK]"
            else:
                output += "[FAIL]"
            output += "\n"

            # Check XS signature
            verified = utils.Crypto.verify_signature(
                self.certificates[signs_cp],
                self.certificates[signs_ticket].signature_pack(),
                self.certificates[signs_ticket].signature
            )
            sha256hash = utils.Crypto.create_sha256hash_hex(self.certificates[signs_ticket].signature_pack())
            output += "    {0} ({1}) signed by {2} ({3}):\n      {4} ".format(
                self.certificates[signs_ticket].get_name(),
                self.certificates[signs_ticket].get_key_type(),
                self.certificates[signs_ticket].get_issuer(),
                self.certificates[signs_cp].get_key_type(),
                sha256hash
            )
            if verified:
                output += "[OK]"
            else:
                output += "[FAIL]"
            output += "\n"

            # Check Root signature
            if signs_ca:
                verified = utils.Crypto.verify_signature(
                    signs_ca,
                    self.certificates[signs_cp].signature_pack(),
                    self.certificates[signs_cp].signature
                )
                sha256hash = utils.Crypto.create_sha256hash_hex(self.certificates[signs_cp].signature_pack())
                output += "    {0} ({1}) signed by {2} ({3}):\n      {4} ".format(
                    self.certificates[signs_cp].get_name(),
                    self.certificates[signs_cp].get_key_type(),
                    self.certificates[signs_cp].get_issuer(),
                    ROOT_KEY.get_key_type(),
                    sha256hash
                )
                if verified:
                    output += "[OK]"
                else:
                    output += "[FAIL]"
            else:
                output += "    {0} ({1}) signed by {2}: Please place root-key in the same directory".format(
                    self.certificates[signs_cp].get_name(),
                    self.certificates[signs_cp].get_key_type(),
                    self.certificates[signs_cp].get_issuer()
                )
            output += "\n"

        return output


class CIA:
    """Represents a CIA file.
       Reference: https://www.3dbrew.org/wiki/CIA

    Args:
        file (Union[str, bytes]): Path to CIA or a CIA bytes-object
    """

    class CIAHeader(Struct):
        def __format__(self):
            self.hdrsize = Struct.uint32
            self.type = Struct.uint16
            self.version = Struct.uint16
            self.certchainsize = Struct.uint32
            self.ticketsize = Struct.uint32
            self.tmdsize = Struct.uint32
            self.metasize = Struct.uint32
            self.contentsize = Struct.uint64
            self.content_index = Struct.uint8[0x2000]

    def __init__(self, file):
        if isinstance(file, str):
            try:
                file = open(file, 'rb').read()
            except FileNotFoundError:
                raise FileNotFoundError('File not found')

        # Header
        self.hdr = self.CIAHeader().unpack(file[:len(self.CIAHeader())])
        pos = self.hdr.hdrsize

        # Certificates (always 3)
        # Order is: Root + XS + CP
        # TODO: Check vailidity of certs (+ dev certs)
        pos += utils.align_pointer(pos)
        self.certificates = []
        for i in range(3):
            self.certificates.append(Certificate(file[pos:]))
            pos += len(self.certificates[i])

        # Ticket
        pos += utils.align_pointer(pos)
        self.ticket = Ticket(file[pos:pos + self.hdr.ticketsize])
        self.ticket.certificates.append(self.certificates[1])  # XS
        self.ticket.certificates.append(self.certificates[0])  # Root
        pos += self.hdr.ticketsize

        # TMD
        pos += utils.align_pointer(pos)
        self.tmd = TMD(file[pos:pos + self.hdr.tmdsize])
        self.tmd.certificates.append(self.certificates[2])  # CP
        self.tmd.certificates.append(self.certificates[0])  # Root
        pos += self.hdr.tmdsize

        # Contents
        pos += utils.align_pointer(pos)
        self.contents = []
        for content in self.tmd.contents:
            content_size = content.size
            self.contents.append(file[pos:pos + content_size])
            pos += content_size

        # Metadata, if present
        pos += utils.align_pointer(pos)
        if file[pos:]:
            self.metadata = file[pos:]
        else:
            self.metadata = None

    def unpack(self, output=None):
        """Extracts CIA to output. Replaces {titleid} and {titleversion} if in foldername.
           Extracts to "extracted_cias/TITLEID/TITLEVER" if no output is given
       """
        if output:
            output = output.format(titleid=self.tmd.get_titleid(), titleversion=self.tmd.hdr.titleversion)
        else:
            output = os.path.join("extracted_cias", self.tmd.get_titleid(), str(self.tmd.hdr.titleversion))
        if not os.path.isdir(output):
            os.makedirs(output)
        self.tmd.dump(os.path.join(output, "tmd"))
        self.ticket.dump(os.path.join(output, "cetk"))
        for num, content in enumerate(self.contents):
            filename = self.tmd.contents[num].get_cid()
            with open(os.path.join(output, filename), "wb") as content_file:
                content_file.write(content)
        if self.metadata:
            with open(os.path.join(output, "meta"), "wb") as meta_file:
                meta_file.write(self.metadata)

    def __repr__(self):
        return "CIA for Title {titleid} v{titlever}".format(
            titleid=self.tmd.get_titleid(),
            titlever=self.tmd.hdr.titleversion
        )

    def __str__(self):
        output = str(self.tmd) + "\n"
        output += str(self.ticket)

        return output


class CIAMaker:
    """Creates a CIA from dir with tmd, cetk and contents
       Reference: https://www.3dbrew.org/wiki/CIA

    Args:
        directory (str): Path to dir with cetk + tmd + contents
        titlever (int): Title Version for TMD (reads tmd.TITLEVER instead of just "tmd")
    """

    class CIAHeader(Struct):
        def __format__(self):
            self.hdrsize = Struct.uint32
            self.type = Struct.uint16
            self.version = Struct.uint16
            self.certchainsize = Struct.uint32
            self.ticketsize = Struct.uint32
            self.tmdsize = Struct.uint32
            self.metasize = Struct.uint32
            self.contentsize = Struct.uint64
            self.content_index = Struct.uint8[0x2000]

    def __init__(self, directory, titlever=None):
        self.directory = directory
        self.ticket = Ticket(os.path.join(self.directory, "cetk"))
        if titlever != None:
            self.tmd = TMD(os.path.join(self.directory, "tmd.{0}".format(titlever)))
        else:
            self.tmd = TMD(os.path.join(self.directory, "tmd"))
        self.contents = []

        # Order of Certs in the CIA: Root Cert, Cetk Cert, TMD Cert (Root + XS + CP)
        # Take the root cert from ticket (can also be taken from the TMD)
        root_cert = self.ticket.certificates[1]
        if root_cert.get_name() != "CA00000003" and root_cert.get_name() != "CA00000004":
            raise Exception("Root Certificate not found")

        cetk_cert = self.ticket.certificates[0]
        if cetk_cert.get_name() != "XS0000000c" and cetk_cert.get_name() != "XS00000009":
            raise Exception("Cetk Certificate not found")

        tmd_cert = self.tmd.certificates[0]
        if tmd_cert.get_name() != "CP0000000b" and tmd_cert.get_name() != "CP0000000a":
            raise Exception("TMD Certificate not found")

        self.certchain = root_cert.pack() + cetk_cert.pack() + tmd_cert.pack()

        # CIA Header
        self.hdr = self.CIAHeader()
        self.hdr.hdrsize = len(self.hdr)
        self.hdr.certchainsize = len(self.certchain)
        self.hdr.ticketsize = len(self.ticket)
        self.hdr.tmdsize = len(self.tmd)
        self.hdr.contentsize = self.tmd.get_content_size()
        for i in range(self.tmd.hdr.contentcount):
            self.hdr.content_index[0] |= 0x80 >> (i & 7)

        # Contents
        for content in self.tmd.contents:
            self.contents.append(open(os.path.join(directory, content.get_cid()), 'rb'))

    def dump(self, output):
        """Dumps CIA to output. Replaces {titleid} and {titleversion} if in filename."""
        output = output.format(titleid=self.tmd.get_titleid(), titleversion=self.tmd.hdr.titleversion)

        # Header
        cia = self.hdr.pack()
        cia += utils.align(len(self.hdr))

        # Certificate Chain
        cia += self.certchain
        cia += utils.align(len(self.certchain))

        # Ticket
        cia += self.ticket.pack()
        cia += utils.align(self.hdr.ticketsize)

        # TMD
        cia += self.tmd.pack()
        cia += utils.align(self.hdr.tmdsize)

        # Writing CIA
        with open(output, "wb") as cia_file:
            cia_file.write(cia)
            # Not forgetting Contents!
            for i, content in enumerate(self.contents):
                for chunk in utils.read_in_chunks(content):
                    cia_file.write(chunk)
                    cia_file.write(utils.align(self.tmd.contents[i].size))
            cia_file.write(utils.align(self.hdr.contentsize))

    def __del__(self):
        for content in self.contents:
            content.close()

    def __repr__(self):
        return "CIA Maker for Title {titleid} v{titlever}".format(
            titleid=self.tmd.get_titleid(),
            titlever=self.tmd.hdr.titleversion
        )

    def __str__(self):
        output = str(self.tmd) + "\n"
        output += str(self.ticket)

        return output


class NUS:
    """Downloads titles from NUS.

    Args:
        titleid (str): Valid hex Title ID (16 chars)
        titlever (int, optional): Valid Title version. Defaults to latest
        base (str, optional): NUS CDN. Defaults to "nus.cdn.c.shop.nintendowifi.net"
    """

    def __init__(
            self,
            titleid,
            titlever=None,
            base="http://nus.cdn.c.shop.nintendowifi.net/ccs/download"
    ):
        self.url = base + "/" + titleid.lower() + "/"
        self._titlever = titlever

    @CachedProperty
    def tmd(self):
        tmd_url = self.url + "tmd"

        if self._titlever != None:
            tmd_url += ".{0}".format(self._titlever)
        try:
            req = get(tmd_url)
            req.raise_for_status()
        except HTTPError:
            raise HTTPError("Title not found on NUS")

        return TMD(req.content)

    @CachedProperty
    def ticket(self):
        cetk_url = self.url + "cetk"
        try:
            req = get(cetk_url)
            req.raise_for_status()
        except HTTPError:
            return None

        return Ticket(req.content)

    def get_content_urls(self):
        """Returns content urls"""
        urls = []
        for content in self.tmd.contents:
            urls.append(self.url + content.get_cid())
        return urls

    def __repr__(self):
        return "Title {id} v{ver} on NUS".format(
            id=self.tmd.get_titleid(),
            ver=self.tmd.hdr.titleversion,
        )

    def __str__(self):
        output = "NUS Content:\n"
        for url in self.get_content_urls():
            output += "  " + url + "\n"

        output += "\n" + str(self.tmd) + "\n"
        if self.ticket:
            output += str(self.ticket)

        return output
