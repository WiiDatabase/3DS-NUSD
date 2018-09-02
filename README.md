3DS-NUSD
========
This is a 3DS NUS downloader written in Python 3(.6). It uses my own [CIAGEN](CIAGEN.py) to create CIAs from CDN content. 3DS-NUSD can even create tickets from encrypted title keys.
It uses the `requests` module, so you'll need to install it with e.g. pip.

"CIAGEN" can create CIAs from cetk + tmd + contents completely in Python without make_cdn_cia. Only thing missing is an implementation of the ticket template (and things listed below in the TODO). It can also unpack a CIA to its CDN contents!

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
  - [X] Use Structs (already in CIAGEN)
  - [X] Improve Struct code (for e.g. ticket template and reading from binary)
  - [ ] More Error handling and retrying
  - [ ] Improve error handling in CIAGEN, especially for certificates and too short tmds/tickets
  - [ ] Support for decrypting & SHA256 verify (via decTitleKeys.bin?)
  - [ ] uselocal parameter (needs SHA256 verifying)
  - [ ] GUI
  
  ## Credits
  * Daeken for original Struct.py
  * ps3hen for [make_cdn_cia](https://github.com/Tiger21820/ctr_toolkit/tree/master/make_cdn_cia)
  * profi200 & contributors for [makerom](https://github.com/profi200/Project_CTR/tree/master/makerom)
  
  ![Screenshot](screenshot.png?raw=true)