#!/usr/bin/env python3
import os

from .certificate import RootKey

if os.path.isfile("root-key"):
    ROOT_KEY = RootKey("root-key")
else:
    ROOT_KEY = None
