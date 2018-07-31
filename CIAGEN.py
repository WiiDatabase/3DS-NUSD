#!/usr/bin/env python3
import binascii
import os
import struct

from requests import get, HTTPError

import utils
from Struct import Struct


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
            raise Exception("Unknown signature type {0}".format(signature_type))
        self.signature = self.signature.unpack(filebytes[:0x04 + self.signature_length])

    def __len__(self):
        return 0x04 + self.signature_length

    def __repr__(self):
        return "{0} Signature Data".format(self.get_signature_type())

    def pack(self):
        return self.signature.pack()

    def get_signature_type(self):
        if self.signature_length == 0x200 + 0x3C:
            return "RSA_4096 SHA256"
        elif self.signature_length == 0x100 + 0x3C:
            return "RSA_2048 SHA256"
        elif self.signature_length == 0x3C + 0x40:
            return "ECDSA SHA256"
        else:
            return "Unknown"


class Certificate(Struct):
    """Represents a Certificate
       Reference: https://www.3dbrew.org/wiki/Certificates
    """
    __endian__ = Struct.BE

    def __format__(self):
        self.issuer = Struct.string(0x40)
        self.key_type = Struct.uint32
        self.name = Struct.string(0x40)
        self.unknown = Struct.uint32


class TMD:
    """Represents the Title Metadata
       Reference: https://www.3dbrew.org/wiki/Title_metadata

    Args:
        f (str): Path to TMD
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

    def __init__(self, f):
        try:
            file = open(f, 'rb')
        except FileNotFoundError:
            raise FileNotFoundError('File not found')

        # Signature
        self.signature = Signature(file.read())
        file.seek(len(self.signature))

        # Header
        self.hdr = self.TMDHeader().unpack(file.read(0xC4))

        # Content Info Records
        self.content_info = []
        for i in range(64):
            self.content_info.append(self.TMDContentInfoRecords().unpack(file.read(0x24)))

        # Content Chunk Records
        self.contents = []
        for i in range(self.hdr.contentcount):
            self.contents.append(self.TMDContents().unpack(file.read(0x30)))

        # Certificates
        self.certificates = []
        for i in range(2):
            self.certificates.append(Certificate())
            cert_offset = file.tell()
            cert_signature = Signature(file.read())
            file.seek(cert_offset + len(cert_signature))
            self.certificates[i].unpack(file.read(0x88))
            self.certificates[i].signature = cert_signature
            self.certificates[i].pubkey = file.read(utils.get_key_length(self.certificates[i].key_type))

    def get_titleid(self):
        return "{:08X}".format(self.hdr.titleid).zfill(16).lower()

    def get_content_size(self):
        size = 0
        for content in self.contents:
            size += content.size
        return size

    def pack(self):
        """Returns TMD WITHOUT certificates."""
        pack = self.signature.pack() + self.hdr.pack()
        for content_info in self.content_info:
            pack += content_info.pack()
        for content in self.contents:
            pack += content.pack()
        return pack

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

        return output


class Ticket:
    """Represents the Ticket
       Reference: https://www.3dbrew.org/wiki/Ticket

    Args:
        f (str): Path to Ticket
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
            self.cid = Struct.string(0xAC)

    def __init__(self, f):
        try:
            file = open(f, 'rb')
        except FileNotFoundError:
            raise FileNotFoundError('File not found')

        # Signature
        self.signature = Signature(file.read())
        file.seek(len(self.signature))

        # Header
        self.hdr = self.TicketHeader().unpack(file.read(0x210))
        self.titleiv = struct.pack(">Q", self.hdr.titleid) + b"\x00" * 8

        # Certificates
        self.certificates = []
        for i in range(2):
            self.certificates.append(Certificate())
            cert_offset = file.tell()
            cert_signature = Signature(file.read())
            file.seek(cert_offset + len(cert_signature))
            self.certificates[i].unpack(file.read(0x88))
            self.certificates[i].signature = cert_signature
            self.certificates[i].pubkey = file.read(utils.get_key_length(self.certificates[i].key_type))

    def get_titleid(self):
        return "{:08X}".format(self.hdr.titleid).zfill(16).lower()

    def pack(self):
        """Returns ticket WITHOUT certificates"""
        return self.signature.pack() + self.hdr.pack()

    def __len__(self):
        """Returns length of ticket WITHOUT certificates"""
        return len(self.signature) + len(self.hdr)

    def __repr__(self):
        return 'Ticket for title {id} v{ver}'.format(id=self.get_titleid(), ver=self.hdr.titleversion)

    def __str__(self):
        output = "Ticket:\n"
        output += "  Title ID: {0}\n".format(self.get_titleid())
        output += "  Ticket Title Version: {0}\n".format(self.hdr.titleversion)
        output += "  Console ID: {0}\n".format(self.hdr.consoleid)
        output += "\n"
        output += "  Initialization vector: {0}\n".format(binascii.hexlify(self.titleiv).decode())
        output += "  Title key (encrypted): {0}\n".format(binascii.hexlify(self.hdr.titlekey).decode())
        if self.hdr.demo == 4:
            output += "  Demo limit active - Max playcount: {0}\n".format(self.hdr.maxplaycount)

        return output


class CIAMaker:
    """Creates a CIA from dir with tmd, cetk and contents
       Reference: https://www.3dbrew.org/wiki/CIA

    Args:
        directory (str): Path to dir with cetk + tmd + contents
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

    def __init__(self, directory):
        self.ticket = Ticket(os.path.join(directory, "cetk"))
        self.tmd = TMD(os.path.join(directory, "tmd"))
        self.contents = []

        # Order of Certs in the CIA: Root Cert, Cetk Cert, TMD Cert (Root + XS + CP)
        # Take the root cert from ticket (can also be taken from the TMD)
        # TODO: Improve certificate class + check if right certificates
        self.certchain = self.ticket.certificates[1].signature.pack()
        self.certchain += self.ticket.certificates[1].pack()
        self.certchain += self.ticket.certificates[1].pubkey

        # Cetk Cert
        self.certchain += self.ticket.certificates[0].signature.pack()
        self.certchain += self.ticket.certificates[0].pack()
        self.certchain += self.ticket.certificates[0].pubkey

        # TMD Cert
        self.certchain += self.tmd.certificates[0].signature.pack()
        self.certchain += self.tmd.certificates[0].pack()
        self.certchain += self.tmd.certificates[0].pubkey

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
    # TODO: Complete this
    """Downloads titles from NUS.

    Args:
        titleid (str): Valid hex Title ID (16 chars)
        titlever (int, optional): Valid Title version. Defaults to latest
        directory (str, optional): Output directory
        base (str, optional): NUS CDN. Defaults to "nus.cdn.c.shop.nintendowifi.net"
    """

    def __init__(
            self,
            titleid,
            titlever=None,
            directory=None,
            base="http://nus.cdn.c.shop.nintendowifi.net/ccs/download"
    ):

        self.url = base + titleid.lower()
        tmd_url = base + "/{0}/tmd".format(titleid)

        if titlever:
            tmd_url += ".{0}".format(titlever)
        try:
            req = get(tmd_url)
            req.raise_for_status()
        except HTTPError:
            print("Title not found on NUS")
            return
