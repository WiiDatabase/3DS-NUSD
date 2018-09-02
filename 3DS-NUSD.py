#!/usr/bin/env python3
import binascii
import os
from argparse import ArgumentParser

from requests import get, HTTPError

import CIAGEN
import utils

BASE_URL = "http://nus.cdn.c.shop.nintendowifi.net/ccs/download"
magic = binascii.a2b_hex('00010004919EBE464AD0F552CD1B72E7884910CF55A9F02E50789641D896683DC005BD0AEA87079D8AC284C675065F74C8BF37C88044409502A022980BB8AD48383F6D28A79DE39626CCB2B22A0F19E41032F094B39FF0133146DEC8F6C1A9D55CD28D9E1C47B3D11F4F5426C2C780135A2775D3CA679BC7E834F0E0FB58E68860A71330FC95791793C8FBA935A7A6908F229DEE2A0CA6B9B23B12D495A6FE19D0D72648216878605A66538DBF376899905D3445FC5C727A0E13E0E2C8971C9CFA6C60678875732A4E75523D2F562F12AABD1573BF06C94054AEFA81A71417AF9A4A066D0FFC5AD64BAB28B1FF60661F4437D49E1E0D9412EB4BCACF4CFD6A3408847982000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000526F6F742D43413030303030303033000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000158533030303030303063000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000137A0894AD505BB6C67E2E5BDD6A3BEC43D910C772E9CC290DA58588B77DCC11680BB3E29F4EABBB26E98C2601985C041BB14378E689181AAD770568E928A2B98167EE3E10D072BEEF1FA22FA2AA3E13F11E1836A92A4281EF70AAF4E462998221C6FBB9BDD017E6AC590494E9CEA9859CEB2D2A4C1766F2C33912C58F14A803E36FCCDCCCDC13FD7AE77C7A78D997E6ACC35557E0D3E9EB64B43C92F4C50D67A602DEB391B06661CD32880BD64912AF1CBCB7162A06F02565D3B0ECE4FCECDDAE8A4934DB8EE67F3017986221155D131C6C3F09AB1945C206AC70C942B36F49A1183BCD78B6E4B47C6C5CAC0F8D62F897C6953DD12F28B70C5B7DF751819A9834652625000100010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010003704138EFBBBDA16A987DD901326D1C9459484C88A2861B91A312587AE70EF6237EC50E1032DC39DDE89A96A8E859D76A98A6E7E36A0CFE352CA893058234FF833FCB3B03811E9F0DC0D9A52F8045B4B2F9411B67A51C44B5EF8CE77BD6D56BA75734A1856DE6D4BED6D3A242C7C8791B3422375E5C779ABF072F7695EFA0F75BCB83789FC30E3FE4CC8392207840638949C7F688565F649B74D63D8D58FFADDA571E9554426B1318FC468983D4C8A5628B06B6FC5D507C13E7A18AC1511EB6D62EA5448F83501447A9AFB3ECC2903C9DD52F922AC9ACDBEF58C6021848D96E208732D3D1D9D9EA440D91621C7A99DB8843C59C1F2E2C7D9B577D512C166D6F7E1AAD4A774A37447E78FE2021E14A95D112A068ADA019F463C7A55685AABB6888B9246483D18B9C806F474918331782344A4B8531334B26303263D9D2EB4F4BB99602B352F6AE4046C69A5E7E8E4A18EF9BC0A2DED61310417012FD824CC116CFB7C4C1F7EC7177A17446CBDE96F3EDD88FCD052F0B888A45FDAF2B631354F40D16E5FA9C2C4EDA98E798D15E6046DC5363F3096B2C607A9D8DD55B1502A6AC7D3CC8D8C575998E7D796910C804C495235057E91ECD2637C9C1845151AC6B9A0490AE3EC6F47740A0DB0BA36D075956CEE7354EA3E9A4F2720B26550C7D394324BC0CB7E9317D8A8661F42191FF10B08256CE3FD25B745E5194906B4D61CB4C2E000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000526F6F7400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001434130303030303030330000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007BE8EF6CB279C9E2EEE121C6EAF44FF639F88F078B4B77ED9F9560B0358281B50E55AB721115A177703C7A30FE3AE9EF1C60BC1D974676B23A68CC04B198525BC968F11DE2DB50E4D9E7F071E562DAE2092233E9D363F61DD7C19FF3A4A91E8F6553D471DD7B84B9F1B8CE7335F0F5540563A1EAB83963E09BE901011F99546361287020E9CC0DAB487F140D6626A1836D27111F2068DE4772149151CF69C61BA60EF9D949A0F71F5499F2D39AD28C7005348293C431FFBD33F6BCA60DC7195EA2BCC56D200BAF6D06D09C41DB8DE9C720154CA4832B69C08C69CD3B073A0063602F462D338061A5EA6C915CD5623579C3EB64CE44EF586D14BAAA8834019B3EEBEED3790001000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
tickettemplate = binascii.a2b_hex('00010004d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000526f6f742d434130303030303030332d585330303030303030630000000000000000000000000000000000000000000000000000000000000000000000000000feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface010000cccccccccccccccccccccccccccccccc00000000000000000000000000aaaaaaaaaaaaaaaa00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010014000000ac000000140001001400000000000000280000000100000084000000840003000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
ticket_siglength = 0x140  # Signature type + Signature + Padding data (0x04 + 0x100 + 0x3C)

parser = ArgumentParser()
parser.add_argument('titleid', type=str, help="Title ID")
parser.add_argument('titleversion', type=int, default=None, nargs="?", help="Title version (default: Latest)")
parser.add_argument(
    '--nopack',
    action='store_false',
    default=True,
    dest='pack_as_cia',
    help='Do not generate CIA.'
)
parser.add_argument(
    '--deletecontents',
    action='store_false',
    default=True,
    dest='keepcontents',
    help='Do not keep contents.'
)
parser.add_argument(
    '--key',
    default=None,
    type=str,
    dest='encrypted_key',
    help='Encrypted title key for Ticket generation.'
)
parser.add_argument(
    '--onlyticket',
    action='store_true',
    default=False,
    dest='onlyticket',
    help='Only create the ticket, don\'t store anything.'
)
arguments = parser.parse_args()


def main(titleid, titlever=None, pack_as_cia=True, keepcontents=True, enc_titlekey=None, onlyticket=False):
    if len(titleid) != 16:
        print("Title ID must be 16 characters long.")
        return
    try:
        int(titleid, 16)
    except ValueError:
        print("Title ID must be in hexadecimal.")
        return

    if onlyticket and not enc_titlekey:
        print("Please specify an ecrypted titlekey (--key) for Ticket generation.")
        return

    if enc_titlekey:
        if len(enc_titlekey) != 32:
            print("Encrypted title key must be 32 characters long.")
            return
        try:
            int(enc_titlekey, 16)
        except ValueError:
            print("Title key must be in hexadecimal.")
            return

    if not pack_as_cia and not keepcontents:
        print("Running with these settings would produce no output.")
        return

    titleid = titleid.lower()
    nus = CIAGEN.NUS(titleid, titlever)

    if onlyticket:
        print("Generating Ticket for Title {0} v{1}".format(titleid, "[Latest]" if titlever == None else titlever))
    else:
        print("Downloading Title {0} v{1}".format(titleid, "[Latest]" if titlever == None else titlever))

    # Download TMD
    print("* Downloading TMD...")
    try:
        tmd = nus.tmd
    except HTTPError:
        print("Title not on NUS!")
        return

    # Parse TMD
    print("* Parsing TMD...")
    total_size = 0
    for content in tmd.contents:
        total_size += content.size
    print("    Title Version: {0}".format(tmd.hdr.titleversion))
    print("    {0} Content{1}: {2}".format(
        len(tmd.contents),
        "s" if len(tmd.contents) > 1 else "",
        utils.convert_size(total_size)
    ))

    if titlever == None:
        titlever = tmd.hdr.titleversion
    else:
        if titlever != tmd.hdr.titleversion:
            print("WARNING: Title version should be {0} but is {1}".format(titleid, tmd.hdr.titleversion))

    if titleid != tmd.get_titleid():
        print("WARNING: Title ID should be {0} but is {1}".format(titleid, tmd.get_titleid()))

    titlepath = os.path.join("titles", titleid, str(titlever))
    if not os.path.exists(titlepath):
        os.makedirs(titlepath)
    if not onlyticket:
        tmd.dump(os.path.join(titlepath, "tmd"))

    # Download Ticket
    if enc_titlekey:
        print("* Generating Ticket...")
        cetk = CIAGEN.Ticket(tickettemplate + magic)
        cetk.hdr.titleid = tmd.hdr.titleid
        cetk.hdr.titleversion = tmd.hdr.titleversion
        cetk.hdr.titlekey = binascii.a2b_hex(enc_titlekey)
        cetk.dump(os.path.join(titlepath, "cetk"))
        if onlyticket:
            print("Finished.")
            return
    else:
        print("* Downloading Ticket...")
        cetk = nus.ticket
        if not cetk:
            if pack_as_cia:
                print("    Ticket unavailable, can't be packed.")
                pack_as_cia = False
            else:
                print("    Ticket unavailable.")
        else:
            cetk.dump(os.path.join(titlepath, "cetk"))

    # Download Contents
    print("* Downloading Contents...")
    for i, content_url in enumerate(nus.get_content_urls()):
        print("    Content #{0} of #{1}: {2} ({3})".format(
            i + 1,
            tmd.hdr.contentcount,
            tmd.contents[i].get_cid(),
            utils.convert_size(tmd.contents[i].size))
        )
        content_path = os.path.join(titlepath, tmd.contents[i].get_cid())
        req = get(content_url, stream=True)
        if req.status_code != 200:
            print("      Failed to download content: Is the title still on the NUS?")
            return
        with open(content_path, 'wb') as content_file:
            for chunk in req.iter_content(chunk_size=5242880):  # Read in 5 MB chunks
                if chunk:
                    content_file.write(chunk)

        if os.path.getsize(content_path) != tmd.contents[i].size:
            print("      Content size mismatch. Abort...")
            return

    # Pack as CIA
    if pack_as_cia:
        print("* Creating CIA...")
        cia_path = os.path.join(titlepath, "{0}-v{1}.cia".format(titleid, titlever))
        CIAGEN.CIAMaker(titlepath).dump(cia_path)
        if not os.path.exists(cia_path):
            print("    CIA creation failed.")
        else:
            print("    CIA creation successful: {0}".format(cia_path))
    else:
        print("Finished.")

    if not keepcontents:
        os.remove(os.path.join(titlepath, "tmd"))
        try:
            os.remove(os.path.join(titlepath, "cetk"))
        except FileNotFoundError:
            pass
        for content in tmd.contents:
            os.remove(os.path.join(titlepath, content.get_cid()))


if __name__ == "__main__":
    main(
        titleid=arguments.titleid,
        titlever=arguments.titleversion,
        pack_as_cia=arguments.pack_as_cia,
        keepcontents=arguments.keepcontents,
        enc_titlekey=arguments.encrypted_key,
        onlyticket=arguments.onlyticket
    )
