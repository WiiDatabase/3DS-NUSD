#!/usr/bin/env python3
from binascii import hexlify

from .certificate import Certificate
from .common import *
from .constants import ROOT_KEY
from .signature import Signature


class TMD:
    """Edits the /title/00000001/00000002/data/setting.txt for the sysmenu.
       Reference: https://github.com/devkitPro/libogc/blob/master/libogc/conf.c

       Args:
           file (str): Path to a TMD file
    """

    class Header(BigEndianStructure):
        _pack_ = 1
        _fields_ = [
            ("issuer", ARRAY(c_byte, 64)),
            ("version", c_uint8),
            ("caCrlVersion", c_uint8),
            ("signerCrlVersion", c_uint8),
            ("reserved1", c_uint8),
            ("systemVersion", c_uint64),
            ("titleid", c_uint64),
            ("type", c_uint32),
            ("groupId", c_uint16),
            ("savedataSize", c_uint32),
            ("srlPrivateDataSize", c_uint32),
            ("reserved2", c_uint32),
            ("srlFlag", c_uint8),
            ("reserved3", ARRAY(c_byte, 49)),
            ("accessRights", c_uint32),
            ("titleversion", c_uint16),
            ("contentCount", c_uint16),
            ("bootContent", c_uint16),
            ("padding", ARRAY(c_byte, 2)),
            ("sha256", ARRAY(c_byte, 32))
        ]

    class ContentInfoRecords(BigEndianStructure):
        _pack_ = 1
        _fields_ = [
            ("cidOffset", c_uint16),
            ("contentCommandCount", c_uint16),
            ("sha256", ARRAY(c_byte, 32))
        ]

        def get_sha256(self):
            """Returns the SHA256 sum as string."""
            return hexlify(self.sha256).decode()

    class ContentChunkRecords(BigEndianStructure):
        _pack_ = 1
        _fields_ = [
            ("id", c_uint32),
            ("index", c_uint16),
            ("type", c_uint16),
            ("size", c_uint64),
            ("sha256", ARRAY(c_byte, 32))
        ]

        def get_cid(self):
            """Returns the content id."""
            return "{:08x}".format(self.id).lower()

        def get_type(self):
            """Returns the content type. Reference: https://www.3dbrew.org/wiki/Title_metadata#Content_Index"""
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

        def get_size_string(self):
            """Returns formatted size."""
            return convert_size(self.size)

        def get_sha256(self):
            """Returns the SHA256 sum as string."""
            return hexlify(self.sha256).decode()

        def __repr__(self):
            return "Content {0} ({1})".format(self.get_cid(), self.get_type())

        def __str__(self):
            output = "   ID         Index   Type           Size       Hash\n"
            output += "   {:s}   {:<7d} {:<14s} {:<10s} {:s}\n".format(
                self.get_cid(),
                self.index,
                self.get_type(),
                self.get_size_string(),
                self.get_sha256()
            )

            return output

    def __init__(self, file):
        if not isinstance(file, bytes):
            with open(str(file), "rb") as fp:
                file = fp.read()

        # Signature
        self.signature = Signature(file)
        pos = sizeof(self.signature)

        # Header
        self.header = self.Header(file[pos:pos + sizeof(self.Header)])
        pos += sizeof(self.header)

        # Content Info Records
        self.contentInfoRecords = []
        for i in range(64):
            self.contentInfoRecords.append(self.ContentInfoRecords(file[pos:pos + sizeof(self.ContentInfoRecords)]))
            pos += sizeof(self.ContentInfoRecords)

        # Content Chunk Records
        self.contents = []
        for i in range(self.get_content_count()):
            self.contents.append(self.ContentChunkRecords(file[pos:pos + sizeof(self.ContentChunkRecords)]))
            pos += sizeof(self.ContentChunkRecords)

        # Certificates
        self.certificates = []
        if file[pos:]:
            for i in range(2):
                self.certificates.append(Certificate(file[pos:]))
                pos += len(self.certificates[i])

    def get_content_count(self):
        """Returns number of contents."""
        return self.header.contentCount

    def get_titleid(self):
        """Returns the title id."""
        return "{:08X}".format(self.header.titleid).zfill(16).lower()

    def get_content_size(self):
        """Returns the size of all contents combined."""
        size = 0
        for content in self.contents:
            size += content.size
        return size

    def get_issuer(self):
        """Returns list with the certificate chain issuers.
           There should be exactly three: the last one (CP) signs the TMD,
           the one before that (CA) signs the CP cert and
           the first one (Root) signs the CA cert.
        """
        return bytes(self.header.issuer).rstrip(b"\00").decode().split("-")

    def get_certificate_by_name(self, name):
        """Returns certificate by name."""
        for i, cert in enumerate(self.certificates):
            if cert.get_name() == name:
                return i
        if name == "Root":
            if ROOT_KEY:
                return ROOT_KEY
        raise ValueError("Certificate '{0}' not found.".format(name))

    def pack(self):
        """Returns TMD WITHOUT certificates."""
        pack = self.signature.pack() + self.pack_signed()
        for content_info in self.contentInfoRecords:
            pack += content_info.pack()
        for content in self.contents:
            pack += content.pack()
        return pack

    def pack_signed(self):
        """Returns only the header (the part that is signed)."""
        return self.header.pack()

    def dump(self, output=None):
        """Dumps TMD to output WITH Certificates. Replaces {titleid} and {titleversion} if in filename.
           Returns raw binary if no output is given, returns the file path else.
        """
        if output:
            output = str(output)
            output = output.format(titleid=self.get_titleid(), titleversion=self.header.titleversion)
        pack = self.pack()
        for cert in self.certificates:
            pack += cert.pack()
        if output:
            with open(output, "wb") as tmd_file:
                tmd_file.write(pack)
                return output
        else:
            return pack

    def __len__(self):
        """Returns length of TMD WITHOUT certificates."""
        size = 0
        for content_info in self.contentInfoRecords:
            size += len(content_info)
        for content in self.contents:
            size += len(content)
        return size + len(self.signature) + len(self.header)

    def __repr__(self):
        return 'Title {id} v{ver}'.format(
            id=self.get_titleid(),
            ver=self.header.titleversion,
        )

    def __str__(self):
        output = "TMD:\n"
        output += "  Title ID: {0}\n".format(self.get_titleid())
        output += "  Title Version: {0}\n".format(self.header.titleversion)
        output += "\n"
        output += "  Number of contents: {0}\n".format(self.header.contentCount)
        output += "  Contents:\n"
        for content in self.contents:
            output += str(content)

        # TODO: Cert cancer

        return output
