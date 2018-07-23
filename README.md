3DS-NUSD
========
This is a 3DS NUS downloader written in Python 3(.6). It uses [make_cdn_cia](https://github.com/Tiger21820/ctr_toolkit/tree/master/make_cdn_cia) (released under the GPLv3) to create CIAs from CDN content. It can even create tickets from encrypted title keys.
It uses the `requests` module, so you'll need to install it with e.g. pip.

## Usage
```
usage: 3DS-NUSD.py [-h] [--nopack] [--deletecontents] [--key ENCRYPTED_KEY]
                   [--onlyticket]
                   titleid [titleversion]

positional arguments:
  titleid              Title ID
  titleversion         Title version (default: Latest)

optional arguments:
  -h, --help           show this help message and exit
  --nopack             Do not generate CIA.
  --deletecontents     Do not keep contents.
  --key ENCRYPTED_KEY  Encrypted title key for Ticket generation.
  --onlyticket         Only create the ticket, don't store anything.
  ```
  
  ## TODO
  - [ ] Use Structs
  - [ ] More Error handling and retrying
  - [ ] Support for decrypting & SHA256 verify
  - [ ] uselocal parameter (needs SHA256 verifying)
  - [ ] GUI