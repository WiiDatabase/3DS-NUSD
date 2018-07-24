#!/usr/bin/env python3
import binascii
import os
import struct

import utils
from Struct import Struct


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

        # Signature data
        self.signature_type = file.read(0x4)
        self.signature_data = file.read(utils.get_sig_size(self.signature_type))

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
        # Certificates
        self.certificates = []
        for i in range(2):
            self.certificates.append(Certificate())
            signature_type = file.read(0x4)
            signature_data = file.read(utils.get_sig_size(signature_type))
            self.certificates[i].unpack(file.read(0x88))
            self.certificates[i].signature_type = signature_type
            self.certificates[i].signature_data = signature_data
            self.certificates[i].pubkey = file.read(utils.get_key_length(self.certificates[i].key_type))

    def get_titleid(self):
        return "{:08X}".format(self.hdr.titleid).zfill(16).lower()

    def get_content_size(self):
        size = 0
        for content in self.contents:
            size += content.size
        return size

    def __len__(self):
        content_info_size = 0
        for content_info in self.content_info:
            content_info_size += len(content_info)
        content_size = 0
        for content in self.contents:
            content_size += len(content)
        return 0x04 + len(self.signature_data) + len(self.hdr) + content_info_size + content_size

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

        # Signature data
        self.signature_type = file.read(0x4)
        self.signature_data = file.read(utils.get_sig_size(self.signature_type))

        # Header
        self.hdr = self.TicketHeader().unpack(file.read(0x210))
        self.titleiv = struct.pack(">Q", self.hdr.titleid) + b"\x00" * 8

        # Certificates
        self.certificates = []
        for i in range(2):
            self.certificates.append(Certificate())
            signature_type = file.read(0x4)
            signature_data = file.read(utils.get_sig_size(signature_type))
            self.certificates[i].unpack(file.read(0x88))
            self.certificates[i].signature_type = signature_type
            self.certificates[i].signature_data = signature_data
            self.certificates[i].pubkey = file.read(utils.get_key_length(self.certificates[i].key_type))

    def get_titleid(self):
        return "{:08X}".format(self.hdr.titleid).zfill(16).lower()

    def __len__(self):
        return 0x04 + len(self.signature_data) + len(self.hdr)

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
        f (str): Path to dir
        out (str): Output path & name
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

    def __init__(self, f, output=None):
        self.ticket = Ticket(os.path.join(f, "cetk"))
        self.tmd = TMD(os.path.join(f, "tmd"))

        # Order of Certs in the CIA: Root Cert, Cetk Cert, TMD Cert (Root + XS + CP)
        # Take the root cert from ticket (can also be taken from the TMD)
        self.certchain = self.ticket.certificates[1].signature_type
        self.certchain += self.ticket.certificates[1].signature_data
        self.certchain += self.ticket.certificates[1].pack()
        self.certchain += self.ticket.certificates[1].pubkey

        # Cetk Cert
        self.certchain += self.ticket.certificates[0].signature_type
        self.certchain += self.ticket.certificates[0].signature_data
        self.certchain += self.ticket.certificates[0].pack()
        self.certchain += self.ticket.certificates[0].pubkey

        # TMD Cert
        self.certchain += self.tmd.certificates[0].signature_type
        self.certchain += self.tmd.certificates[0].signature_data
        self.certchain += self.tmd.certificates[0].pack()
        self.certchain += self.tmd.certificates[0].pubkey

        # CIA Header
        self.hdr = self.CIAHeader()
        self.hdr.hdrsize = 0x2020
        self.hdr.certchainsize = len(self.certchain)
        self.hdr.ticketsize = len(self.ticket)
        self.hdr.tmdsize = len(self.tmd)
        self.hdr.contentsize = self.tmd.get_content_size()
        for i in range(self.tmd.hdr.contentcount):
            self.hdr.content_index[0] |= 0x80 >> (i & 7)
        cia = self.hdr.pack()
        cia += utils.align(len(self.hdr))

        # Certificate Chain
        cia += self.certchain
        cia += utils.align(len(self.certchain))

        # Ticket
        cia += self.ticket.signature_type + self.ticket.signature_data + self.ticket.hdr.pack()
        cia += utils.align(self.hdr.ticketsize)

        # TMD
        cia += self.tmd.signature_type + self.tmd.signature_data + self.tmd.hdr.pack()
        for content_info in self.tmd.content_info:
            cia += content_info.pack()
        for content in self.tmd.contents:
            cia += content.pack()
        cia += utils.align(self.hdr.tmdsize)

        # TODO: Improve this, bit complicated with content files (should not be in memory)
        if not output:
            output = os.path.join(f, "{titleid}-v{titleversion}.cia")
        output = output.format(titleid=self.tmd.get_titleid(), titleversion=self.tmd.hdr.titleversion)
        with open(output, "wb") as cia_file:
            cia_file.write(cia)
            # Contents
            for content in self.tmd.contents:
                with open(os.path.join(f, content.get_cid()), 'rb') as content_file:
                    for chunk in utils.read_in_chunks(content_file):
                        cia_file.write(chunk)
                        cia_file.write(utils.align(content.size))
            cia += utils.align(self.hdr.contentsize)
