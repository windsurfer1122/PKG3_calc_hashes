#!/usr/bin/env python3
# -*- coding: utf-8; tab-width: 4; indent-tabs-mode: nil; py-indent-offset: 4 -*-
### ^^^ see https://www.python.org/dev/peps/pep-0263/

###
### PKG3_calc_hashes.py (c) 2018-2019 by "windsurfer1122"
### Calculate hashes for data blocks inside PS3/PSX/PSP/PSV/PSM packages.
### Use at your own risk!
###
### For options execute: PKG3_calc_hashes.py -h and read the README.md
###
### git master repository at https://github.com/windsurfer1122
### Read README.md for more information including Python requirements and more
###
### Python 2 backward-compatible workarounds:
### - handle prefix in kwargs manually
### - set system default encoding to UTF-8
### - define unicode() for Python 3 like in Python 2 (ugly)
### - convert byte string of struct.pack()/.unpack() to bytearray()
###
### Adopted PEP8 Coding Style: (see https://www.python.org/dev/peps/pep-0008/)
### * (differs to PEP8) Studly_Caps_With_Underscores for global variables
### * (differs to PEP8) mixedCase for functions, methods
### * lower_case_with_underscores for attributes, variables
### * UPPER_CASE_WITH_UNDERSCORES for constants
### * StudlyCaps for classes
###

###
### This program is free software: you can redistribute it and/or modify
### it under the terms of the GNU General Public License as published by
### the Free Software Foundation, either version 3 of the License, or
### (at your option) any later version.
###
### This program is distributed in the hope that it will be useful,
### but WITHOUT ANY WARRANTY; without even the implied warranty of
### MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
### GNU General Public License for more details.
###
### You should have received a copy of the GNU General Public License
### along with this program.  If not, see <https://www.gnu.org/licenses/>.
###

### Python 2 future-compatible workarounds: (see: http://python-future.org/compatible_idioms.html)
## a) prevent interpreting print(a,b) as a tuple plus support print(a, file=sys.stderr)
from __future__ import print_function
## b) interpret all literals as unicode
from __future__ import unicode_literals
## c) same division handling ( / = float, // = integer)
from __future__ import division
## d) interpret long as int, support int.from_bytes()
from builtins import int
## e) support bytes()
from builtins import bytes


## Version definition
## see https://www.python.org/dev/peps/pep-0440/
__version__ = "2019.07.01"
__author__ = "https://github.com/windsurfer1122/PKG3_calc_hashes"
__license__ = "GPL"
__copyright__ = "Copyright 2018-2019, windsurfer1122"


## Imports
import sys
import struct
import io
import requests
import collections
import locale
import os
import argparse
import re
import traceback
import json
import random
import aenum
import base64
import xml.etree.ElementTree
import copy

import Cryptodome.Cipher.AES
import Cryptodome.Hash
import Cryptodome.PublicKey.RSA
import Cryptodome.Signature.pkcs1_15


## Debug level for Python initializations (will be reset in "main" code)
Debug_Level = 0


## Error and Debug print to stderr
## https://stackoverflow.com/questions/5574702/how-to-print-to-stderr-in-python
def eprint(*args, **kwargs):  ## error print
    ## Python 2 workaround: handle prefix in kwargs manually
    #def eprint(*args, prefix="[ERROR] ", **kwargs):  ## Python 3 only
    if "prefix" in kwargs:
        prefix = kwargs["prefix"]
        del kwargs["prefix"]
    else:
        prefix="[ERROR] "
    #
    if not prefix is None \
    and prefix != "":
        print(prefix, file=sys.stderr, end="")
    print(*args, file=sys.stderr, **kwargs)

def dprint(*args, **kwargs):  ## debug print
    if Debug_Level:
        ## Python 2 workaround: handle prefix in kwargs manually
        #def dprint(*args, prefix="[debug] ", **kwargs):  ## Python 3 only
        if "prefix" in kwargs:
            prefix = kwargs["prefix"]
            del kwargs["prefix"]
        else:
            prefix="[debug] "
        #
        if not prefix is None \
        and prefix != "":
            print(prefix, file=sys.stderr, end="")
        print(*args, file=sys.stderr, **kwargs)


## Enhanced TraceBack
## http://code.activestate.com/recipes/52215-get-more-information-from-tracebacks/
## https://stackoverflow.com/questions/27674602/hide-traceback-unless-a-debug-flag-is-set
def print_exc_plus():
    """
    Print the usual traceback information, followed by a listing of
    important variables in each frame.
    """
    tb = sys.exc_info()[2]
    stack = []

    while tb:
        stack.append(tb.tb_frame)
        tb = tb.tb_next

    for frame in stack:
        for key, value in frame.f_locals.items():
            if key != "Source":
                continue
            eprint(">>> PKG Source:", end=" ")
            #We have to be careful not to cause a new error in our error
            #printer! Calling str() on an unknown object could cause an
            #error we don't want.
            try:
                eprint(value, prefix=None)
            except:
                eprint("<ERROR WHILE PRINTING VALUE>", prefix=None)

    traceback.print_exc()


## General debug information related to Python
if Debug_Level >= 1:
    dprint("Python Version", sys.version)

## Python 2/Windows workaround: set system default encoding to UTF-8 like in Python 3
## All results will be Unicode and we want all output to be UTF-8
try:
    reload
except NameError:
    ## Python 3.4+
    from importlib import reload
reload(sys)
if sys.getdefaultencoding().lower() != "utf-8":
    if Debug_Level >= 1:
        dprint("Default Encoding setting from {} to UTF-8".format(sys.getdefaultencoding()))
    sys.setdefaultencoding("utf-8")
if sys.stdout.encoding \
and sys.stdout.encoding.lower() != "utf-8":
    if Debug_Level >= 1:
        dprint("STDOUT Encoding setting from {} to UTF-8".format(sys.stdout.encoding))
    sys.stdout.reconfigure(encoding="utf-8")
if sys.stderr.encoding \
and sys.stderr.encoding.lower() != "utf-8":
    if Debug_Level >= 1:
        dprint("STDERR Encoding setting from {} to UTF-8".format(sys.stderr.encoding))
    sys.stderr.reconfigure(encoding="utf-8")

## General debug information related to Unicode
if Debug_Level >= 1:
    ## List encodings
    dprint("DEFAULT Encoding", sys.getdefaultencoding())
    dprint("LOCALE Encoding", locale.getpreferredencoding())
    dprint("STDOUT Encoding {} Terminal {}".format(sys.stdout.encoding, sys.stdout.isatty()))
    dprint("STDERR Encoding {} Terminal {}".format(sys.stderr.encoding, sys.stderr.isatty()))
    dprint("FILESYS Encoding", sys.getfilesystemencoding())
    value = ""
    if "PYTHONIOENCODING" in os.environ:
        value = os.environ["PYTHONIOENCODING"]
    dprint("PYTHONIOENCODING=", value, sep="")
    ## Check Unicode
    dprint("ö ☺ ☻")

## Python 2/3 workaround: define unicode for Python 3 like in Python 2
## Unfortunately a backward-compatible workaround, as I couldn't find a forward-compatible one :(
## Every string is Unicode
## https://stackoverflow.com/questions/34803467/unexpected-exception-name-basestring-is-not-defined-when-invoking-ansible2
try:
    unicode
except:
    if Debug_Level >= 1:
        dprint("Define \"unicode = str\" for Python 3 :(")
    unicode = str

### pycryptodome/x <3.7.2 CMAC error workaround
### https://github.com/Legrandin/pycryptodome/issues/238
Version = re.match("(\d+)\.(\d+)", Cryptodome.__version__)
Version_Check = [ int(Version.group(1)), int(Version.group(2)) ]
#
if (Version_Check[0] == 3 \
    and Version_Check[1] >= 7) \
or Version_Check[0] > 3:
    dprint("pycryptodome/x", Cryptodome.__version__, "is good")
    ### https://www.pycryptodome.org/en/latest/src/hash/cmac.html
    def newCMAC(key):
       return Cryptodome.Hash.CMAC.new(key, ciphermod=Cryptodome.Cipher.AES)
    def getCMACDigest(self):
       return self.digest()
else:
    dprint("pycryptodome/x < 3.7.2 has an error in CMAC copying, therefore switching to module cryptography for CMAC hashing")
    import cryptography.hazmat.backends
    import cryptography.hazmat.primitives.hashes
    import cryptography.hazmat.primitives.cmac
    import cryptography.hazmat.primitives.ciphers.algorithms
    ### https://cryptography.io/en/latest/hazmat/primitives/mac/cmac/
    def newCMAC(key):
       return cryptography.hazmat.primitives.cmac.CMAC(cryptography.hazmat.primitives.ciphers.algorithms.AES(key), backend=cryptography.hazmat.backends.default_backend())
    def getCMACDigest(self):
       return self.finalize()


## Generic Definitions
CONST_READ_SIZE = random.randint(50,100) * 0x100000  ## Read in 50-100 MiB chunks to reduce memory usage and swapping
CONST_READ_AHEAD_SIZE = 128 * 0x400 ## Read first 128 KiB to reduce read requests (fits header of known PS3/PSX/PSP/PSV/PSM packages; Kib/Mib = 0x400/0x100000; biggest header + Items Info found was 2759936 = 0x2a1d00 = ~2.7 MiB)
#
CONST_USER_AGENT_PS3 = "Mozilla/5.0 (PLAYSTATION 3; 4.84)"
#CONST_USER_AGENT_PSP = ""
CONST_USER_AGENT_PSV = " libhttp/3.70 (PS Vita)"
CONST_USER_AGENT_PS4 = "Download/1.00 libhttp/6.71 (PlayStation 4)"
#
CONST_HASH_MD5 = "MD5"
CONST_HASH_SHA1 = "SHA1"
CONST_HASH_SHA256 = "SHA256"
CONST_HASH_CMAC = "CMAC"
CONST_HASH_DIGEST = "DIGEST"
CONST_HASH_RSA = "RSA"
CONST_HASH_HMAC = "HMAC"
CONST_HASHES = {
    CONST_HASH_MD5: { "SIZE": 16, "MODULE": Cryptodome.Hash.MD5, },
    CONST_HASH_SHA1: { "SIZE": 20, "MODULE": Cryptodome.Hash.SHA1, },
    CONST_HASH_SHA256: { "SIZE": 32, "MODULE": Cryptodome.Hash.SHA256, },
    CONST_HASH_CMAC: { "SIZE": 16, },
    CONST_HASH_DIGEST: { "SIZE": 0x40, },
}
## --> Platforms
class CONST_BLOCK_TYPE(aenum.OrderedEnum):
    def __str__(self):
        return unicode(self.value)

    __ordered__ = "DATA VERIFY"
    DATA = "main data"
    VERIFY = "verify data"

##
## PKG3 Definitions
##
#
## --> PKG Content and Update Keys
## http://www.psdevwiki.com/ps3/Keys#gpkg-key
## https://playstationdev.wiki/psvitadevwiki/index.php?title=Keys#Content_PKG_Keys
CONST_PKG3_AES_KEYS = {
  -1: { "KEY": bytes.fromhex("00000000000000000000000000000000"), "DESC": "Zero key", },
   0: { "KEY": "Lntx18nJoU6jIh8YiCi4+A==", "DESC": "PS3 Content Key [default]",     },
   1: { "KEY": "B/LGgpC1DSwzgY1wm2DmKw==", "DESC": "PSX/PSP Content Key", },
   2: { "KEY": "4xpwyc4d1yvzwGIpY/Lsyw==", "DESC": "PSV Content Key",     "DERIVE": True, },
   3: { "KEY": "QjrKOivVZJ+Whqutb9iAHw==", "DESC": "Unknown Content Key", "DERIVE": True, },
   4: { "KEY": "rwf9WWUlJ7rxM4lmixfZ6g==", "DESC": "PSM Content Key",     "DERIVE": True, },
   5: { "KEY": "5eJ4qh7jQIKgiCecg/m7yAaCHFLyq10rSr2ZVFA1URQ=", "DESC": "PSV Update Key", },
}
for Key, Values in CONST_PKG3_AES_KEYS.items():
    if isinstance(Values["KEY"], unicode):
        Values["KEY"] = base64.standard_b64decode(Values["KEY"])
    elif isinstance(Values["KEY"], bytes) \
    or isinstance(Values["KEY"], bytearray):
        if Key != -1:
            eprint("PKG3 Content Key #{}:".format(Key), base64.standard_b64encode(Values["KEY"]), prefix="[CONVERT] ")
del Values
del Key
## --> PKG RSA Public Keys 2048 bit (=256/0x100 bytes)
## https://playstationdev.wiki/psvitadevwiki/index.php?title=Keys#RSA_PKG_Keys
CONST_PKG3_RSA_PUB_EXP = 0x010001
CONST_PKG3_RSA_PUB_KEYS = {
   0: { "KEY": "u9tqoy47UabUcI1fyYmZGTlaKq2D6Y9IZMO6Q6XWkG9HbnNTW/qO+cNyCCah8ie4/wb2nzmWOYdjXr/7ylHQ+47WvxeLvqj2rt1ktAE5KQU/Fpt+rZdpjnXAYK2tzHAm7/5TFnL53RoRcY1KTl1DoWJfUzYGmSV86hoFFJnDH/fkr8y5qdoucDHI5GjBYS0aDrwi9CswouU9gCvFrOinGYuQkgKsvCNOf8fYMhE3s7KtDw0JhdyJE2P6o62NN5rWWnGUrqCdwpB708iIllZUV6ZZpmKq1Ob7QBiyzfGIbEPhaq3hq6deiHn2udVFx8TQJWcQfN4cGsxD5Ru/uFGd1Q==", "DESC": "\"PSP\" [default]", },
   1: { "KEY": "hdcveaZ8mgTSaRsdLTAnSnMc9iTjvGj+izutne+1B4TEu69j1cxDERmREoiFTjjqYddXGzPrEsetO81GEPocobTHfSBFUNb3KrHmgKRgnM+JC5U6rGzc2u2fECcphDkUykqIvLiNQe4NwOTT5lenlQEoB8UArhOgtEJH1eQLX55KzvRsD6KILfP1EJYca4rhE57mYTUM3Yx6XU+cHNVeBEnLAGWojPY3ZmT2xPUir8nFVvFqNtp5+CLSjTwvY93RGOYrFivHPivhsT+Dke7kYnDYIMi786AjaD6h0HnXtNby9VenOhaKoj+IKs/bqaCzfH6urmuIuGnezdaJKBOmww==", "DESC": "\"PSV\"", },
   2: { "KEY": "jlw7Bc7PwMoTKMJQCddAsnN2II9nisRU0BW7PmezfQWwmZC2f2wP5j4wrHzJPLKhyDUXzM3zeuei3j4fgXkZsZRPWrycAMhG0BqaXgFP8Vw7hAZpriXQa6BEnvbtHBTXI+upFRdWuU2lJl+TrjZIFr4VIoWwGlbjgPKFrSEG1rVB2VCyyEumhVmzoQEVQDeAioWITTp0YSr3b2i2RqcP6w7yRIdmcbfLL/DRzJJrfP+MRAwSrjIuOh6ihW78okvZuJZ8PyYDjvRLJq8jpoSBS84ogGuB3JInzjh/OCCvE/upZPOjQ9aSFU7r65F6voYehO6tcowwozRziVN26f3GLQ==", "DESC": "\"LiveArea\"", },
}
for Key, Values in CONST_PKG3_RSA_PUB_KEYS.items():
    if isinstance(Values["KEY"], unicode):
        Values["KEY"] = base64.standard_b64decode(Values["KEY"])
        Values["SIZE"] = len(Values["KEY"])
        Values["RSA"] = Cryptodome.PublicKey.RSA.construct((int.from_bytes(Values["KEY"], byteorder="big"), CONST_PKG3_RSA_PUB_EXP))
    elif isinstance(Values["KEY"], bytes) \
    or isinstance(Values["KEY"], bytearray):
        if Key >= 0:
            eprint("PKG3 Content Key #{}:".format(Key), base64.standard_b64encode(Values["KEY"]), prefix="[CONVERT] ")
del Values
del Key


def convertBytesToHexString(data, format="", sep=" "):
    if isinstance(data, int):
        data = struct.pack(format, data)
    ## Python 2 workaround: convert byte string of struct.pack()/.unpack() to bytearray()
    if isinstance(data, str):
        data = bytearray(data)
    #
    return sep.join(["%02x" % b for b in data])


class PkgInputReader():
    def __init__(self, source, function_debug_level=0):
        self._source = source
        self._pkg_name = None
        self._size = None
        self._multipart = False
        self._partscount = None
        self._parts = []
        #
        self._buffer = None
        self._buffer_size = 0
        #
        self._headers = {"User-Agent": CONST_USER_AGENT_PS3}  ## Default to PS3 headers (fits PS3/PSX/PSP/PSV packages, but not PSM packages for PSV)

        ## Check for multipart package
        ## --> XML
        if self._source.endswith(".xml"):
            input_stream = None
            xml_root = None
            xml_element = None
            if self._source.startswith("http:") \
            or self._source.startswith("https:"):
                if function_debug_level >= 2:
                    dprint("[INPUT] Opening source as URL XML data stream")
                try:
                    input_stream = requests.get(self._source, headers=self._headers)
                except:
                    eprint("[INPUT] Could not open URL", self._source)
                    if input_stream:
                        if input_stream.url != self._source:
                            eprint("[INPUT] Redirected URL", input_stream.url)
                        eprint("[INPUT]", input_stream.status_code, input_stream.reason)
                    eprint("", prefix=None)
                    raise  ## re-raise
                if input_stream.status_code != requests.codes.ok:
                    eprint("[INPUT] Could not open URL", self._source)
                    if input_stream.url != self._source:
                        eprint("[INPUT] Redirected URL", input_stream.url)
                    eprint("[INPUT]", input_stream.status_code, input_stream.reason)
                    raise input_stream.raise_for_status()
                if function_debug_level >= 3:
                    if input_stream.url != self._source:
                        dprint("[INPUT] Redirected URL", input_stream.url)
                    dprint("[INPUT]", input_stream.status_code, input_stream.reason)
                    dprint("[INPUT] Response headers:", input_stream.headers)
                xml_root = xml.etree.ElementTree.fromstring(input_stream.text)
                input_stream.close()
            else:
                if function_debug_level >= 2:
                    dprint("[INPUT] Opening source as FILE XML data stream")
                try:
                    input_stream = io.open(self._source, mode="rt", buffering=-1, encoding=None, errors=None, newline=None, closefd=True)
                except:
                    eprint("[INPUT] Could not open FILE", self._source)
                    eprint("", prefix=None)
                    raise  ## re-raise
                xml_root = xml.etree.ElementTree.fromstring(input_stream.read())
                input_stream.close()
            del input_stream
            #
            ## Check for known XML
            if xml_root.tag != CONST_PKG3_XML_ROOT:
                eprint("[INPUT] Not a known PKG XML file ({} <> {})".format(xml_root.tag, CONST_PKG3_XML_ROOT), self._source)
                eprint("", prefix=None)
                sys.exit(2)
            ## Determine values from XML data
            xml_element = xml_root.find("file_name")
            if not xml_element is None:
                self._pkg_name = xml_element.text.strip()
            #
            xml_element = xml_root.find("file_size")
            if not xml_element is None:
                self._size = int(xml_element.text.strip())
            #
            xml_element = xml_root.find("number_of_split_files")
            if not xml_element is None:
                self._partscount = int(xml_element.text.strip())
                if self._partscount > 1:
                    self._multipart = True
            ## Determine file parts from XML data
            for xml_element in xml_root.findall("pieces"):
                xml_element.attrib["INDEX"] = int(xml_element.attrib["index"])
                del xml_element.attrib["index"]
                #
                xml_element.attrib["SIZE"] = int(xml_element.attrib["file_size"])
                del xml_element.attrib["file_size"]
                #
                self._parts.append(xml_element.attrib)
            #
            self._parts = sorted(self._parts, key=lambda x: (x["INDEX"]))
            #
            offset = 0
            file_part = None
            for file_part in self._parts:
                file_part["START_OFS"] = offset
                file_part["END_OFS"] = file_part["START_OFS"] + file_part["SIZE"]
                offset += file_part["SIZE"]
                #
                if function_debug_level >= 2:
                    dprint("[INPUT] Pkg Part #{} Offset {:#012x} Size {} \"{}\"".format(file_part["INDEX"], file_part["START_OFS"], file_part["SIZE"], file_part["url"]))
            del file_part
            del offset
            #
            del xml_element
            del xml_root
        ## --> JSON
        elif self._source.endswith(".json"):
            self._headers = {"User-Agent": CONST_USER_AGENT_PS4}  ## Switch to PS4 headers
            input_stream = None
            json_data = None
            if self._source.startswith("http:") \
            or self._source.startswith("https:"):
                if function_debug_level >= 2:
                    dprint("[INPUT] Opening source as URL JSON data stream")
                try:
                    input_stream = requests.get(self._source, headers=self._headers)
                except:
                    eprint("[INPUT] Could not open URL", self._source)
                    if input_stream:
                        if input_stream.url != self._source:
                            eprint("[INPUT] Redirected URL", input_stream.url)
                        eprint("[INPUT]", input_stream.status_code, input_stream.reason)
                    eprint("", prefix=None)
                    raise  ## re-raise
                if input_stream.status_code != requests.codes.ok:
                    eprint("[INPUT] Could not open URL", self._source)
                    if input_stream.url != self._source:
                        eprint("[INPUT] Redirected URL", input_stream.url)
                    eprint("[INPUT]", input_stream.status_code, input_stream.reason)
                    raise input_stream.raise_for_status()
                if function_debug_level >= 3:
                    if input_stream.url != self._source:
                        dprint("[INPUT] Redirected URL", input_stream.url)
                    dprint("[INPUT]", input_stream.status_code, input_stream.reason)
                    dprint("[INPUT] Response headers:", input_stream.headers)
                json_data = input_stream.json()
                input_stream.close()
            else:
                if function_debug_level >= 2:
                    dprint("[INPUT] Opening source as FILE JSON data stream")
                try:
                    input_stream = io.open(self._source, mode="rt", buffering=-1, encoding=None, errors=None, newline=None, closefd=True)
                except:
                    eprint("[INPUT] Could not open FILE", self._source)
                    eprint("", prefix=None)
                    raise  ## re-raise
                json_data = json.load(input_stream)
                input_stream.close()
            del input_stream
            #
            ## Check for known JSON
            if not "pieces" in json_data \
            or not json_data["pieces"][0] \
            or not "url" in json_data["pieces"][0]:
                eprint("[INPUT] JSON source does not look like PKG meta data (missing [pieces][0])", self._source)
                eprint("", prefix=None)
                sys.exit(2)
            ## Determine values from JSON data
            if "originalFileSize" in json_data:
                self._size = json_data["originalFileSize"]
            #
            if "numberOfSplitFiles" in json_data:
                self._partscount = json_data["numberOfSplitFiles"]
                if self._partscount > 1:
                    self._multipart = True
            ## Determine file parts from JSON data
            if "pieces" in json_data:
                json_data["pieces"] = sorted(json_data["pieces"], key=lambda x: (x["fileOffset"]))
                #
                count = 0
                file_part = None
                for file_part in json_data["pieces"]:
                    if not self._pkg_name:
                        if file_part["url"].startswith("http:") \
                        or file_part["url"].startswith("https:"):
                            self._pkg_name = os.path.basename(requests.utils.urlparse(file_part["url"]).path).strip()
                        else:
                            self._pkg_name = os.path.basename(file_part["url"]).strip()
                        #
                        self._pkg_name = re.sub(r"_[0-9]+\.pkg$", r".pkg", self._pkg_name, flags=re.UNICODE)
                    #
                    file_part["INDEX"] = count
                    count += 1
                    #
                    file_part["START_OFS"] = file_part["fileOffset"]
                    del file_part["fileOffset"]
                    #
                    file_part["SIZE"] = file_part["fileSize"]
                    del file_part["fileSize"]
                    #
                    file_part["END_OFS"] = file_part["START_OFS"] + file_part["SIZE"]
                    #
                    self._parts.append(file_part)
                    #
                    if function_debug_level >= 2:
                        dprint("[INPUT] Pkg Part #{} Offset {:#012x} Size {} \"{}\"".format(file_part["INDEX"], file_part["START_OFS"], file_part["SIZE"], file_part["url"]))
                del file_part
                del count
            #
            del json_data
        else:
            if self._source.startswith("http:") \
            or self._source.startswith("https:"):
                if function_debug_level >= 2:
                    dprint("[INPUT] Using source as URL PKG data stream")
                self._pkg_name = os.path.basename(requests.utils.urlparse(self._source).path).strip()
            else:
                if function_debug_level >= 2:
                    dprint("[INPUT] Using source as FILE PKG data stream")
                self._pkg_name = os.path.basename(self._source).strip()
            #
            self._multipart = False
            self._partscount = 1
            #
            file_part = {}
            file_part["INDEX"] = 0
            file_part["START_OFS"] = 0
            file_part["url"] = self._source
            self._parts.append(file_part)
            if function_debug_level >= 2:
                dprint("[INPUT] Pkg Part #{} Offset {:#012x} \"{}\"".format(file_part["INDEX"], file_part["START_OFS"], file_part["url"]))
            del file_part
            #
            self.open(self._parts[0], function_debug_level=max(0,function_debug_level))
            if "SIZE" in self._parts[0]:
                self._size = self._parts[0]["SIZE"]

        read_size = CONST_READ_AHEAD_SIZE
        if read_size > self._size:
            read_size = self._size
        if read_size > 0:
            self._buffer = self.read(0, read_size, function_debug_level=max(0,function_debug_level))
            self._buffer_size = len(self._buffer)
            if function_debug_level >= 2:
                dprint("[INPUT] Buffered first {} bytes of package".format(self._buffer_size), "(max {})".format(CONST_READ_AHEAD_SIZE) if self._buffer_size != CONST_READ_AHEAD_SIZE else "")

    def getSize(self, function_debug_level=0):
        return self._size

    def getSource(self, function_debug_level=0):
        return self._source

    def getPkgName(self, function_debug_level=0):
        return self._pkg_name

    def open(self, file_part, function_debug_level=0):
        ## Check if already opened
        if "STREAM" in file_part:
            return

        part_size = None
        response = None
        if file_part["url"].startswith("http:") \
        or file_part["url"].startswith("https:"):
            if function_debug_level >= 2:
                dprint("[INPUT] Opening Pkg Part #{} as URL PKG data stream".format(file_part["INDEX"]))
            ## Persistent session
            ## http://docs.python-requests.org/en/master/api/#request-sessions
            file_part["STREAM_TYPE"] = "requests"
            try:
                file_part["STREAM"] = requests.Session()
            except:
                eprint("[INPUT] Could not create HTTP/S session for PKG URL", file_part["url"])
                eprint("", prefix=None)
                raise  ## re-raise
            #
            file_part["STREAM"].headers = self._headers
            try:
                response = file_part["STREAM"].head(file_part["url"], allow_redirects=True, timeout=60)
            except:
                eprint("[INPUT] Could not open URL", file_part["url"])
                if response:
                    if response.url != file_part["url"]:
                        eprint("[INPUT] Redirected URL", response.url)
                    eprint("[INPUT]", response.status_code, response.reason)
                eprint("", prefix=None)
                raise  ## re-raise
            if response.status_code != requests.codes.ok:
                eprint("[INPUT] Could not open URL", file_part["url"])
                if response.url != file_part["url"]:
                    eprint("[INPUT] Redirected URL", response.url)
                eprint("[INPUT]", response.status_code, response.reason)
                raise response.raise_for_status()
            if function_debug_level >= 3:
                if response.url != file_part["url"]:
                    dprint("[INPUT] Redirected URL", response.url)
                dprint("[INPUT]", response.status_code, response.reason)
                dprint("[INPUT] Response headers:", response.headers)
            if "content-length" in response.headers:
                part_size = int(response.headers["content-length"])
        else:
            if function_debug_level >= 3:
                dprint("[INPUT] Opening Pkg Part #{} as FILE PKG data stream".format(file_part["INDEX"]))
            #
            file_part["STREAM_TYPE"] = "file"
            try:
                file_part["STREAM"] = io.open(file_part["url"], mode="rb", buffering=-1, encoding=None, errors=None, newline=None, closefd=True)
            except:
                eprint("[INPUT] Could not open PKG FILE", file_part["url"])
                eprint("", prefix=None)
                raise  ## re-raise
            #
            file_part["STREAM"].seek(0, io.SEEK_END)
            part_size = file_part["STREAM"].tell()

        ## Check file size
        if not part_size is None:
            if not "SIZE" in file_part:
                file_part["SIZE"] = part_size
                file_part["END_OFS"] = file_part["START_OFS"] + file_part["SIZE"]
            else:
                if part_size != file_part["SIZE"]:
                    if not response is None:
                        eprint("[INPUT]", response.status_code, response.reason)
                        eprint("[INPUT] Response headers:", response.headers)
                    eprint("[INPUT] File size differs from XML/JSON meta data ({} <> {})".format(part_size, file_part["SIZE"]))
                    eprint("", prefix=None)
                    sys.exit(2)

        if function_debug_level >= 3:
            dprint("[INPUT] Data stream is of class", file_part["STREAM"].__class__.__name__)

    def read(self, offset, size, function_debug_level=0):
        result = bytearray()
        read_offset = offset
        read_size = size

        if read_size < 0:
            raise ValueError("Negative read size {}".format(read_size))

        if self._buffer \
        and self._buffer_size > read_offset \
        and read_size > 0:
            read_buffer_size = read_size
            if (read_offset+read_buffer_size) > self._buffer_size:
                read_buffer_size = self._buffer_size-read_offset
            #
            if function_debug_level >= 3:
                dprint("[INPUT] Get offset {:#012x} size {}/{} bytes from buffer".format(read_offset, read_buffer_size, size))
            #
            result.extend(self._buffer[read_offset:read_offset+read_buffer_size])
            #
            read_offset += read_buffer_size
            read_size -= read_buffer_size

        count = 0
        lastcount = -1
        while read_size > 0:
            while count < self._partscount \
            and self._parts[count]["START_OFS"] <= read_offset:
                count += 1
            count -= 1
            if lastcount == count:  ## Avoid endless loop
                raise ValueError("[INPUT] Read offset {:#012x} out of range (max. {:#012x})".format(read_offset, self._size-1))
            lastcount = count
            #
            file_part = self._parts[count]
            #
            file_offset = read_offset - file_part["START_OFS"]
            #
            read_buffer_size = read_size
            if (read_offset+read_buffer_size) > file_part["END_OFS"]:
                read_buffer_size = file_part["END_OFS"]-read_offset
            #
            if function_debug_level >= 3:
                dprint("[INPUT] Read offset {:#012x} size {}/{} bytes from Pkg Part #{} Offset {:#012x}".format(read_offset, read_buffer_size, size, file_part["INDEX"], file_offset))
            #
            self.open(file_part, function_debug_level=max(0,function_debug_level))
            #
            if file_part["STREAM_TYPE"] == "file":
                file_part["STREAM"].seek(file_offset, io.SEEK_SET)
                result.extend(file_part["STREAM"].read(read_buffer_size))
                ## supports the following.
                ## * offset=9000 + size=-1 => all bytes from offset 9000 to the end
                ## does *NOT* support the following, have to calculate size from file size.
                ## * bytes=-32 => last 32 bytes
            elif file_part["STREAM_TYPE"] == "requests":
                ## Send request in persistent session
                ## http://docs.python-requests.org/en/master/api/#requests.Session.get
                ## http://docs.python-requests.org/en/master/api/#requests.request
                ## https://www.rfc-editor.org/info/rfc7233
                ## supports the following.
                ## * bytes=9000- => all bytes from offset 9000 to the end
                ## * bytes=-32 => last 32 bytes
                reqheaders={"Range": "bytes={}-{}".format(file_offset, (file_offset + read_buffer_size - 1) if read_buffer_size > 0 else "")}
                response = file_part["STREAM"].get(file_part["url"], headers=reqheaders, timeout=60)
                result.extend(response.content)
            #
            read_offset += read_buffer_size
            read_size -= read_buffer_size

        return result

    def close(self, function_debug_level=0):
        for file_part in self._parts:
            if not "STREAM" in file_part:
                continue

            file_part["STREAM"].close()
            del file_part["STREAM"]

        return


def newVerifyBlock(number, check):
    verify_block = {}
    verify_block["NUMBER"] = number
    verify_block["TYPE"] = CONST_BLOCK_TYPE.VERIFY
    verify_block["CHECK"] = check
    verify_block["SIZE"] = None
    verify_block["HASH"] = None
    verify_block["KEY"] = None
    return verify_block


def displayBlock(block, block_prefix=None, print_func=print, **kwargs):
    if "prefix" in kwargs \
    and print_func == print:
        del kwargs["prefix"]
    #
    if block_prefix:
        print_func(block_prefix, end="", **kwargs)
    else:
        print_func("Block #{}:".format(block["NUMBER"]), end="", **kwargs)
    #
    if print_func != print:
        kwargs["prefix"] = None
    #
    print_func(" StartOfs +{:#012x}".format(block["STARTOFS"]), end="", **kwargs)
    if "ORGSTARTOFS" in block:
        print_func(" ({})".format(block["ORGSTARTOFS"]), end="", **kwargs)
    #
    if "SIZE" in block \
    and not block["SIZE"] is None:
        print_func(" Size +{}".format(block["SIZE"]), end="", **kwargs)
    #
    if "ENDOFS" in block \
    and not block["ENDOFS"] is None:
        print_func(" EndOfs +{:#012x}".format(block["ENDOFS"]), end="", **kwargs)
    if "ORGENDOFS" in block:
        print_func(" ({})".format(block["ORGENDOFS"]), end="", **kwargs)
    #
    print_func(**kwargs)


def addHash(hash, key, target):
    if hash == CONST_HASH_CMAC:
        if not hash in target:
            target[hash] = {}
        if not key in target[hash]:
            target[hash][key] = None
    else:
        if not hash in target:
            target[hash] = None


def updateAllHashes(hashes, data):
    for key, element in hashes.items():
        if isinstance(element, dict):
            updateAllHashes(element, data)
        else:
            element.update(data)


def copyAllHashes(source, target, digest, parent_digest_func=None):
    for key, element in source.items():
        digest_func = parent_digest_func
        if key == CONST_HASH_CMAC:
            digest_func = getCMACDigest
        #
        if isinstance(element, dict):
            target[key] = {}
            digest[key] = {}
            copyAllHashes(element, target[key], digest[key], parent_digest_func=digest_func)
        else:
            target[key] = element.copy()
            if not digest_func is None:
                digest[key] = digest_func(target[key])
            else:
                digest[key] = target[key].digest()


def createArgParser():
    ## argparse: https://docs.python.org/3/library/argparse.html

    ## Create help texts
    ## --> Hex Values
    help_hexvalues = "Sources are not used as file path or URL.\n\
They are used directly as hex data.\n\
Block definitions are ignored."
    ## --> Values
    help_values = "Sources are not used as file path or URL.\n\
They are used directly as data encoded in UTF-8.\n\
Block definitions are ignored."
    ## --> Extra
    help_extra = "Calculate extra hashes. All types with all known keys."
    ## --> Block
    help_block = "=<[-]startofs>,<+size|[-]endofs>[,<verify:digest|sha1|sha256|cmac[-<key>]|rsa[-<key>]>[,<[-]verifyofs>]]\n\
Data Block to build hashes and/or check RSA signatures for.\n\
NOTE: Equal sign is recommended and necessary for start offsets with dash/\n\
      minus symbol for relative offsets to file end.\n"
    #
    help_block = "".join((help_block, "Available PKG3 AES Keys:\n"))
    for key, values in CONST_PKG3_AES_KEYS.items():
        if key < 0:
            continue
        #
        help_block = "".join((help_block, "  {:#2} = {}\n".format(key, values["DESC"])))
    #
    help_block = "".join((help_block, "Available PKG3 RSA Public Keys:\n"))
    for key, values in CONST_PKG3_RSA_PUB_KEYS.items():
        help_block = "".join((help_block, "  {:#2} = {}\n".format(key, values["DESC"])))
    ## --> Show
    help_show = "Show all blocks, e.g. verify data blocks, and not only main data blocks."
    ## --> Debug
    choices_debug = range(4)
    help_debug = "Debug verbosity level.\n\
  0 = No debug info [default]\n\
  1 = Show calculated file block offsets and sizes\n\
  2 = Additionally show read actions\n\
  3 = Additionally show parsed options and internal stuff"

    ## Create description
    description = "%(prog)s {version}\n{copyright}\n{author}\n\
Calculate hashes and verify hashes plus RSA signatures for data blocks in PS3/PSX/PSP/PSV/PSM packages.".format(version=__version__, copyright=__copyright__, author=__author__)
    ## Create epilog
    epilog = "If you state URLs then only the necessary bytes are downloaded into memory."

    ## Build Arg Parser
    parser = argparse.ArgumentParser(description=description, epilog=epilog, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-V", "--version", action="version", version=__version__)
    parser.add_argument("source", metavar="SOURCE", nargs="+", help="Path or URL to PKG/XML/JSON file")
    parser.add_argument("--values", action="store_true", help=help_values)
    parser.add_argument("--hexvalues", action="store_true", help=help_hexvalues)
    parser.add_argument("--extra", action="store_true", help=help_extra)
    parser.add_argument("--block", "-b", action="append", help=help_block)
    parser.add_argument("--show", action="store_true", help=help_show)
    parser.add_argument("--debug", "-d", metavar="LEVEL", type=int, default=0, choices=choices_debug, help=help_debug)

    return parser


## Global code
if __name__ == "__main__":
    try:
        ## Check parameters from command line
        Exit_Code = 0
        Parser = createArgParser()
        Arguments = Parser.parse_args()
        ## Global Debug [Verbosity] Level: can be set via '--debug='/'-d'
        Debug_Level = Arguments.debug
        ## List of block definitions: can be set via '--block'/'-b'
        Blocks = []
        if Arguments.block:
            Argument_Value = None
            Block_Number = 0
            Block = None
            Block_Count = None
            Skip = None
            Block_StartOfs = None
            Block_Size = None
            Block_EndOfs = None
            for Argument_Value in Arguments.block:
                Block_Number += 1
                Block = Argument_Value.split(",")
                Block_Count = len(Block)
                if Block_Count < 2:
                    eprint("Option --block #{}: block value {} is not valid (offset,size[,verifyhash])".format(Block_Number, Argument_Value))
                    Exit_Code = 2
                    continue

                ## Parse main block definition
                ## --> Start offset and size/end offset
                Skip = False
                #
                try:
                    Block_StartOfs = int(Block[0], 0)
                except:
                    eprint("Option --block #{}: start offset value {} is not a number".format(Block_Number, Block[0]))
                    Exit_Code = 2
                    Skip = True
                #
                try:
                    if Block[1][0] == "+":
                        Block_Size = int(Block[1], 0)
                        Block_EndOfs = None
                        #
                        if Block_Size <= 0:
                            eprint("Option --block #{}: size value {} is not valid".format(Block_Number, Block_Size))
                            Exit_Code = 2
                            Skip = True
                    else:
                        Block_Size = None
                        Block_EndOfs = int(Block[1], 0)
                except:
                    eprint("Option --block #{}: size/end offset value {} is not a number".format(Block_Number, Block[1]))
                    Exit_Code = 2
                    Skip = True
                #
                if Skip:
                    continue

                ## Check block
                if not Block_EndOfs is None:
                    ## Check start and end offset if are both either relative or absolute
                    if ((Block_StartOfs < 0 and Block_EndOfs <= 0) \
                          or (Block_StartOfs >= 0 and Block_EndOfs > 0)):
                        if Block_EndOfs <= Block_StartOfs:
                            eprint("Option --block #{}: end offset value {} invalid (<= start offset value {})".format(Block_Number, Block_EndOfs, Block_StartOfs))
                            Exit_Code = 2
                            continue
                        #
                        Block_Size = Block_EndOfs - Block_StartOfs
                elif not Block_Size is None:
                    if Block_StartOfs >= 0:
                        Block_EndOfs = Block_StartOfs + Block_Size
                    else:
                        if abs(Block_StartOfs) < Block_Size:
                            eprint("Option --block #{}: size value +{} invalid (> start offset value {})".format(Block_Number, Block_Size, Block_StartOfs))
                            Exit_Code = 2
                            continue

                ## Create main block
                New_Block = {}   ## collections.OrderedDict()
                New_Block["NUMBER"] = Block_Number
                New_Block["TYPE"] = CONST_BLOCK_TYPE.DATA
                New_Block["STARTOFS"] = Block_StartOfs
                New_Block["SIZE"] = Block_Size
                New_Block["ENDOFS"] = Block_EndOfs
                New_Block["VERIFY"] = []

                ## Parse verify options
                if Block_Count > 2:
                    Value = None
                    Upper_Value = None
                    Verify_Block = None
                    for Value in Block[2:]:
                        Upper_Value = Value.upper()
                        if Upper_Value == CONST_HASH_MD5:
                            Verify_Block = newVerifyBlock(New_Block["NUMBER"], CONST_HASH_MD5)
                            Verify_Block["SIZE"] = CONST_HASHES[CONST_HASH_MD5]["SIZE"]
                            Verify_Block["HASH"] = CONST_HASH_MD5
                            New_Block["VERIFY"].append(Verify_Block)
                        elif Upper_Value == CONST_HASH_SHA1 \
                        or Upper_Value == "SHA" \
                        or Upper_Value == "SHA-1":
                            Verify_Block = newVerifyBlock(New_Block["NUMBER"], CONST_HASH_SHA1)
                            Verify_Block["SIZE"] = CONST_HASHES[CONST_HASH_SHA1]["SIZE"]
                            Verify_Block["HASH"] = CONST_HASH_SHA1
                            New_Block["VERIFY"].append(Verify_Block)
                        elif Upper_Value == CONST_HASH_SHA256 \
                        or Upper_Value == "SHA-256":
                            Verify_Block = {}
                            Verify_Block = newVerifyBlock(New_Block["NUMBER"], CONST_HASH_SHA256)
                            Verify_Block["SIZE"] = CONST_HASHES[CONST_HASH_SHA256]["SIZE"]
                            Verify_Block["HASH"] = CONST_HASH_SHA256
                            New_Block["VERIFY"].append(Verify_Block)
                        elif Upper_Value == CONST_HASH_DIGEST:
                            Verify_Block = newVerifyBlock(New_Block["NUMBER"], CONST_HASH_DIGEST)
                            Verify_Block["SIZE"] = CONST_HASHES[CONST_HASH_DIGEST]["SIZE"]
                            Verify_Block["HASH"] = CONST_HASH_CMAC
                            Verify_Block["KEY"] = 0
                            Verify_Block["HASH2"] = CONST_HASH_SHA1
                            Verify_Block["KEY2"] = None
                            New_Block["VERIFY"].append(Verify_Block)
                        elif Upper_Value == CONST_HASH_CMAC \
                        or Upper_Value.startswith("CMAC-"):
                            Verify_Block = newVerifyBlock(New_Block["NUMBER"], CONST_HASH_CMAC)
                            Verify_Block["SIZE"] = CONST_HASHES[CONST_HASH_CMAC]["SIZE"]
                            Verify_Block["HASH"] = CONST_HASH_CMAC
                            #
                            Check_Value = Value.split("-")
                            if len(Check_Value) > 1:
                                try:
                                    Verify_Block["KEY"] = int(Check_Value[1], 0)
                                    #
                                    if not Verify_Block["KEY"] in CONST_PKG3_AES_KEYS:
                                        eprint("Option --block #{}: {} refers to an unknown AES key".format(New_Block["NUMBER"], Value))
                                        Exit_Code = 2
                                except:
                                    eprint("Option --block #{}: {} refers to a AES key which is not a number".format(New_Block["NUMBER"], Value))
                                    Exit_Code = 2
                            else:
                                Verify_Block["KEY"] = 0
                            del Check_Value
                            #
                            New_Block["VERIFY"].append(Verify_Block)
                        elif Upper_Value == CONST_HASH_RSA \
                        or Upper_Value.startswith("RSA-"):
                            Verify_Block = newVerifyBlock(New_Block["NUMBER"], CONST_HASH_RSA)
                            Verify_Block["HASH"] = CONST_HASH_SHA1  ## TODO: allow other hashes too
                            #
                            Check_Value = Value.split("-")
                            if len(Check_Value) > 1:
                                try:
                                    Verify_Block["KEY"] = int(Check_Value[1], 0)
                                    #
                                    if not Verify_Block["KEY"] in CONST_PKG3_RSA_PUB_KEYS:
                                        eprint("Option --block #{}: {} refers to an unknown RSA public key".format(New_Block["NUMBER"], Value))
                                        Exit_Code = 2
                                    else:
                                        Verify_Block["SIZE"] = CONST_PKG3_RSA_PUB_KEYS[Verify_Block["KEY"]]["SIZE"]
                                except:
                                    eprint("Option --block #{}: {} refers to a RSA public key which is not a number".format(New_Block["NUMBER"], Value))
                                    Exit_Code = 2
                            else:
                                Verify_Block["KEY"] = 0
                                Verify_Block["SIZE"] = CONST_PKG3_RSA_PUB_KEYS[Verify_Block["KEY"]]["SIZE"]
                            del Check_Value
                            #
                            New_Block["VERIFY"].append(Verify_Block)
                        else:
                            if Verify_Block is None:
                                eprint("Option --block #{}: verify value {} is neither a supported/known hash type nor assigned to one".format(New_Block["NUMBER"], Value))
                                Exit_Code = 2
                                continue
                            else:
                                try:
                                    Verify_Block["STARTOFS"] = int(Value, 0)
                                except:
                                    eprint("Option --block #{}: verify value {} is neither a known hash type nor a number".format(New_Block["NUMBER"], Value))
                                    Exit_Code = 2
                                Verify_Block = None
                    #
                    del Verify_Block
                    del Upper_Value
                    del Value

                ## Add main block to definition list
                Blocks.append(New_Block)
                del New_Block
            ##
            del Block_EndOfs
            del Block_Size
            del Block_StartOfs
            del Skip
            del Block_Count
            del Block
            del Block_Number
            del Argument_Value

        if Exit_Code == 0 \
        and not Arguments.values \
        and not Arguments.hexvalues \
        and not Blocks:
            eprint("No blocks stated")
            Exit_Code = 2
        #
        if Arguments.values \
        and Arguments.hexvalues:
            eprint("Either specify --values or --hexvalues")
            Exit_Code = 2
        #
        if Exit_Code:
            Parser.print_help()
            sys.exit(Exit_Code)

        if Debug_Level >= 3:
            dprint("Blocks from command line:")
            Index = None
            Values = None
            for Index, Values in enumerate(Blocks):
                dprint("{}:".format(Index), Values)
            del Values
            del Index

        ## Process paths and URLs
        for Source in Arguments.source:
            if Arguments.values \
            or Arguments.hexvalues:
                ## Process value
                print(">>>>>>>>>> Value:", Source)
                if Arguments.values:
                    Data_Bytes = Source.encode("UTF-8")
                elif Arguments.hexvalues:
                    Data_Bytes = bytes.fromhex(Source)
                #
                print("Data bytes:", convertBytesToHexString(Data_Bytes, sep=""), "({})".format(len(Data_Bytes)))

                ## Create hash digest
                Hashes = {}
                ## Plain hashes (MD5, SHA-1, SHA-256, etc.)
                for Hash_Key, Hash_Values in CONST_HASHES.items():
                    if not "MODULE" in Hash_Values:
                        continue
                    #
                    Hashes[Hash_Key] = Hash_Values["MODULE"].new(Data_Bytes).digest()
                    print("  {}:".format(Hash_Key), convertBytesToHexString(Hashes[Hash_Key], sep=""))
                del Hash_Values
                del Hash_Key
                ## CMAC (AES)
                print("  CMAC")
                Hashes[CONST_HASH_CMAC] = {}
                for Key, Values in CONST_PKG3_AES_KEYS.items():
                    if Arguments.extra \
                    or Key == 0:  ## Hash for PKG3 Digest CMAC 0x040
                        Hashes[CONST_HASH_CMAC][Key] = newCMAC(Values["KEY"])
                        Hashes[CONST_HASH_CMAC][Key].update(Data_Bytes)
                        Hashes[CONST_HASH_CMAC][Key] = Hashes[CONST_HASH_CMAC][Key].digest()
                        print("    AES Key #{}:".format(Key), convertBytesToHexString(Hashes[CONST_HASH_CMAC][Key], sep=""), " ({})".format(Values["DESC"]))
                del Values
                del Key
                ## HMAC hashes (AES)
                Hashes[CONST_HASH_HMAC] = {}
                for Hash_Key, Hash_Values in CONST_HASHES.items():
                    if not "MODULE" in Hash_Values:
                        continue
                    #
                    if Arguments.extra \
                    or (Hash_Key == CONST_HASH_SHA256):  ## Hash for PSV Update Link with Key #5
                        print("  HMAC-{}".format(Hash_Key))
                        Hashes[CONST_HASH_HMAC][Hash_Key] = {}
                        for Key, Values in CONST_PKG3_AES_KEYS.items():
                            if Arguments.extra \
                            or (Hash_Key == CONST_HASH_SHA256
                                and Key == 5):  ## Hash for PSV Update Link
                                Hashes[CONST_HASH_HMAC][Hash_Key][Key] = Cryptodome.Hash.HMAC.new(Values["KEY"], digestmod=Hash_Values["MODULE"], msg=Data_Bytes).digest()
                                print("    AES Key #{}:".format(Key), convertBytesToHexString(Hashes[CONST_HASH_HMAC][Hash_Key][Key], sep=""), " ({})".format(Values["DESC"]))
                        del Values
                        del Key
                del Hash_Values
                del Hash_Key
                #
                del Data_Bytes
            else:
                ## Open PKG source
                print("# >>>>>>>>>> PKG Source:", Source)
                #
                try:
                    Input_Stream = PkgInputReader(Source, function_debug_level=max(0, Debug_Level))
                except requests.exceptions.HTTPError:
                    continue
                File_Size = Input_Stream.getSize(function_debug_level=max(0, Debug_Level))
                print("File Size:", File_Size)

                ## Convert blocks to file blocks
                File_Blocks = []
                Block = None
                File_Block = None
                Relative_Offset = None
                Block_Offset = None
                for Block in Blocks:
                    ## Create new file block
                    File_Block = copy.copy(Block)
                    del File_Block["VERIFY"]
                    File_Block["VERIFY"] = []
                    File_Block["HASHES"] = {}
                    File_Block["DIGESTS"] = {}

                    ## 1.) Handle main block
                    ## --> start offset
                    if File_Block["STARTOFS"] < 0:
                        if not File_Size:
                            eprint("Block #{}:".format(File_Block["NUMBER"]), "Skipped as its start offset could not be calculated without a file size", prefix="[WARNING] ")
                            displayBlock(File_Block, print_func=eprint, prefix="[WARNING]  ")
                            continue
                        #
                        Relative_Offset = File_Block["STARTOFS"]
                        Block_Offset = File_Size + Relative_Offset
                        #
                        if Block_Offset < 0:  ## still negative
                            eprint("Block #{}:".format(File_Block["NUMBER"]), "Skipped as its start offset", File_Block["STARTOFS"], "does not fit file size", File_Size, prefix="[WARNING] ")
                            displayBlock(File_Block, print_func=eprint, prefix="[WARNING]  ")
                            continue
                        #
                        File_Block["STARTOFS"] = Block_Offset
                        File_Block["ORGSTARTOFS"] = Relative_Offset
                    #
                    if File_Size \
                    and File_Block["STARTOFS"] >= File_Size:
                        eprint("Block #{}:".format(File_Block["NUMBER"]), "Skipped as its start offset", File_Block["STARTOFS"], "does not fit file size", File_Size, prefix="[WARNING] ")
                        displayBlock(File_Block, print_func=eprint, prefix="[WARNING]  ")
                        continue

                    ## --> end offset
                    if File_Block["ENDOFS"] is None:
                        File_Block["ENDOFS"] = File_Block["STARTOFS"] + File_Block["SIZE"]
                    elif File_Block["ENDOFS"] <= 0:
                        if not File_Size:
                            eprint("Block #{}:".format(File_Block["NUMBER"]), "Skipped as its end offset could not be calculated without a file size", prefix="[WARNING] ")
                            displayBlock(File_Block, print_func=eprint, prefix="[WARNING]  ")
                            continue
                        #
                        Relative_Offset = File_Block["ENDOFS"]
                        Block_Offset = File_Size + Relative_Offset
                        #
                        if Block_Offset < 0:  ## still negative
                            eprint("Block #{}:".format(File_Block["NUMBER"]), "Skipped as its end offset", File_Block["ENDOFS"], "does not fit file size", File_Size, prefix="[WARNING] ")
                            displayBlock(File_Block, print_func=eprint, prefix="[WARNING]  ")
                            continue
                        #
                        File_Block["ENDOFS"] = Block_Offset
                        File_Block["ORGENDOFS"] = Relative_Offset
                    #
                    if File_Size \
                    and File_Block["ENDOFS"] > File_Size:
                        eprint("Block #{}:".format(File_Block["NUMBER"]), "Skipped as its end offset", File_Block["ENDOFS"], "does not fit file size", File_Size, prefix="[WARNING] ")
                        displayBlock(File_Block, print_func=eprint, prefix="[WARNING]  ")
                        continue

                    ## -->  size
                    if File_Block["SIZE"] is None:
                        File_Block["SIZE"] = File_Block["ENDOFS"] - File_Block["STARTOFS"]
                    #
                    if File_Block["SIZE"] <= 0:
                        eprint("Block #{}:".format(File_Block["NUMBER"]), "Skipped as its size", File_Block["SIZE"], "is invalid (<=0)", prefix="[WARNING] ")
                        displayBlock(File_Block, print_func=eprint, prefix="[WARNING]  ")
                        continue

                    ## 2.) Handle verify blocks
                    Verify_Block = None
                    Block_Prefix = None
                    for Verify_Block in Block["VERIFY"]:
                        Verify_Block = copy.deepcopy(Verify_Block)
                        Block_Prefix = "Block #{} Verify {}:".format(Verify_Block["NUMBER"], Verify_Block["CHECK"])
                        ## --> start offset
                        if "STARTOFS" in Verify_Block:
                            if Verify_Block["STARTOFS"] < 0:
                                if not File_Size:
                                    eprint(Block_Prefix, "Skipped as its start offset could not be calculated without a file size", prefix="[WARNING] ")
                                    displayBlock(Verify_Block, block_prefix=Block_Prefix, print_func=eprint, prefix="[WARNING]  ")
                                    continue
                                #
                                Relative_Offset = Verify_Block["STARTOFS"]
                                Block_Offset = File_Size + Relative_Offset
                                #
                                if Block_Offset < 0:  ## still negative
                                    eprint(Block_Prefix, "Skipped as its start offset", Verify_Block["STARTOFS"], "does not fit file size", File_Size, prefix="[WARNING] ")
                                    displayBlock(Verify_Block, block_prefix=Block_Prefix, print_func=eprint, prefix="[WARNING]  ")
                                    continue
                                #
                                Verify_Block["STARTOFS"] = Block_Offset
                                Verify_Block["ORGSTARTOFS"] = Relative_Offset
                        else:
                            Verify_Block["STARTOFS"] = File_Block["ENDOFS"]
                        #
                        if File_Size \
                        and Verify_Block["STARTOFS"] >= File_Size:
                            eprint(Block_Prefix, "Skipped as its start offset", Verify_Block["STARTOFS"], "does not fit file size", File_Size, prefix="[WARNING] ")
                            displayBlock(Verify_Block, block_prefix=Block_Prefix, print_func=eprint, prefix="[WARNING]  ")
                            continue

                        ## --> end offset
                        Verify_Block["ENDOFS"] = Verify_Block["STARTOFS"] + Verify_Block["SIZE"]
                        #
                        if File_Size \
                        and Verify_Block["ENDOFS"] > File_Size:
                            eprint(Block_Prefix, "Skipped as its end offset", Verify_Block["ENDOFS"], "does not fit file size", File_Size, prefix="[WARNING] ")
                            displayBlock(Verify_Block, block_prefix=Block_Prefix, print_func=eprint, prefix="[WARNING]  ")
                            continue

                        ## Add verify block to main file block again and also as separate file block to process list (note: same reference/object used in both lists)
                        Verify_Block["DATA"] = bytearray()
                        File_Block["VERIFY"].append(Verify_Block)
                        File_Blocks.append(Verify_Block)
                    #
                    del Block_Prefix
                    del Verify_Block

                    ## Add main file block to process list
                    File_Blocks.append(File_Block)
                #
                del Block_Offset
                del Relative_Offset
                del File_Block
                del Block

                ## Sort file blocks by calculated offsets and sizes for further processing
                File_Blocks = sorted(File_Blocks, key=lambda x: (x["STARTOFS"], x["ENDOFS"]))
                #
                if Debug_Level >= 1:
                    dprint("File Blocks (by offsets):")
                    Index = None
                    File_Block = None
                    for Index, File_Block in enumerate(File_Blocks):
                        dprint("{}:".format(Index), File_Block)
                    del File_Block
                    del Index

                ## Calculate file parts out of sorted file blocks
                File_Parts = []
                File_Part = None
                File_Block = None
                for File_Block in File_Blocks:
                    ## Check if file block starts a new file part (nothing interleaves)
                    if File_Part is None \
                    or File_Block["STARTOFS"] >= File_Part["ENDOFS"]:
                        File_Part = collections.OrderedDict()
                        File_Part["STARTOFS"] = File_Block["STARTOFS"]
                        File_Part["ENDOFS"] = File_Block["ENDOFS"]
                        File_Part["TYPE"] = File_Block["TYPE"]
                        File_Part["OFFSETS"] = []
                        File_Part["HASHES"] = {}
                        ## Plain hashes (MD5, SHA-1, SHA-256, etc.)
                        for Hash_Key, Hash_Values in CONST_HASHES.items():
                            if not "MODULE" in Hash_Values:
                                continue
                            #
                            File_Part["HASHES"][Hash_Key] = None
                        del Hash_Values
                        del Hash_Key
                        ## CMAC (AES)
                        if Arguments.extra:
                            File_Part["HASHES"][CONST_HASH_CMAC] = {}
                            for Key, Values in CONST_PKG3_AES_KEYS.items():
                                File_Part["HASHES"][CONST_HASH_CMAC][Key] = None
                            del Values
                            del Key
                        ## HMAC hashes (AES)
                        if Arguments.extra:
                            File_Part["HASHES"][CONST_HASH_HMAC] = {}
                            for Hash_Key, Hash_Values in CONST_HASHES.items():
                                if not "MODULE" in Hash_Values:
                                    continue
                                #
                                File_Part["HASHES"][CONST_HASH_HMAC][Hash_Key] = {}
                                for Key, Values in CONST_PKG3_AES_KEYS.items():
                                    File_Part["HASHES"][CONST_HASH_HMAC][Hash_Key][Key] = None
                            del Values
                            del Key
                            del Hash_Values
                            del Hash_Key
                        #
                        File_Parts.append(File_Part)
                    ## File block extends current file part
                    elif File_Block["ENDOFS"] > File_Part["ENDOFS"]:
                        File_Part["ENDOFS"] = File_Block["ENDOFS"]
                        if File_Part["TYPE"] != CONST_BLOCK_TYPE.DATA:
                            File_Part["TYPE"] = File_Block["TYPE"]

                    ## Collect offsets
                    File_Part["OFFSETS"].extend((File_Block["STARTOFS"], File_Block["ENDOFS"]))
                    #
                    if not Arguments.extra \
                    and "VERIFY" in File_Block:
                        Values = None
                        for Values in File_Block["VERIFY"]:
                            addHash(Values["HASH"], Values["KEY"], File_Part["HASHES"])
                            if "HASH2" in Values:
                                addHash(Values["HASH2"], Values["KEY2"], File_Part["HASHES"])
                        del Values
                del File_Part
                del File_Block

                ## For each file part do a unique sort of its offsets
                Index = None
                File_Part = None
                if Debug_Level >= 1:
                    dprint("File Parts:")
                for Index, File_Part in enumerate(File_Parts):
                    File_Part["OFFSETS"] = sorted(set(File_Part["OFFSETS"]))
                    #
                    if Debug_Level >= 1:
                            dprint("{}:".format(Index), File_Part)
                del File_Part
                del Index

                ## Read each file part in chunks derived from the offsets
                ## and calculate hashes for each file block
                ## For definition see http://www.psdevwiki.com/ps3/PKG_files#0x40_digest
                File_Part = None
                Hashes = None
                for File_Part in File_Parts:
                    Hashes = {}
                    #
                    Index = None
                    Block_Offset = None
                    for Index, Block_Offset in enumerate(File_Part["OFFSETS"][:-1]):
                        ## Determine next offset from next list element and calculate size
                        Next_Offset = File_Part["OFFSETS"][Index+1]
                        Block_Size = Next_Offset - Block_Offset

                        ## Add hash entries for new offset
                        if File_Part["TYPE"] == CONST_BLOCK_TYPE.DATA:
                            Hashes[Block_Offset] = copy.deepcopy(File_Part["HASHES"])
                            #
                            for Hash_Key, Hash_Values in Hashes[Block_Offset].items():
                                if Hash_Key == CONST_HASH_HMAC:
                                    for Hash_Key2, Hash_Values2 in Hash_Values.items():
                                        for Key, Values in Hash_Values2.items():
                                            Hash_Values2[Key] = Cryptodome.Hash.HMAC.new(CONST_PKG3_AES_KEYS[Key]["KEY"], digestmod=CONST_HASHES[Hash_Key2]["MODULE"])
                                        del Values
                                        del Key
                                    del Hash_Values2
                                    del Hash_Key2
                                elif Hash_Key == CONST_HASH_CMAC:
                                    for Key, Values in Hash_Values.items():
                                        Hash_Values[Key] = newCMAC(CONST_PKG3_AES_KEYS[Key]["KEY"])
                                    del Values
                                    del Key
                                else:
                                    Hashes[Block_Offset][Hash_Key] = CONST_HASHES[Hash_Key]["MODULE"].new()
                            del Hash_Values
                            del Hash_Key

                        ## Get data from file
                        if Debug_Level >= 2:
                            dprint("Retrieve offset {:#012x} size {}".format(Block_Offset, Block_Size))
                        Data_Bytes = None
                        while Block_Size > 0:
                            if Block_Size > CONST_READ_SIZE:
                                Size = CONST_READ_SIZE
                            else:
                                Size = Block_Size
                            if Debug_Level >= 3:
                                dprint("...offset {:#012x} size {}".format(Block_Offset, Size))
                            Data_Bytes = bytes(Input_Stream.read(Block_Offset, Size, function_debug_level=max(0, Debug_Level)))

                            ## Update hashes with data (recursively)
                            updateAllHashes(Hashes, Data_Bytes)

                            ## Update verify blocks with data
                            for File_Block in File_Blocks:
                                if File_Block["TYPE"] == CONST_BLOCK_TYPE.VERIFY \
                                and File_Block["STARTOFS"] <= Block_Offset \
                                and File_Block["ENDOFS"] >= Next_Offset:
                                    File_Block["DATA"].extend(Data_Bytes)
                            del File_Block

                            ## Prepare next iteration
                            Block_Size -= Size
                            Block_Offset += Size
                        #
                        del Data_Bytes

                        ## Check if any file block got completed and copy the hashes for it (recursively)
                        for File_Block in File_Blocks:
                            if File_Block["ENDOFS"] != Next_Offset:
                                continue
                            #
                            if Debug_Level >= 2:
                                dprint("Block #{} {} completed".format(File_Block["NUMBER"], File_Block["TYPE"]))
                            #
                            if File_Block["TYPE"] == CONST_BLOCK_TYPE.DATA:
                                copyAllHashes(Hashes[File_Block["STARTOFS"]], File_Block["HASHES"], File_Block["DIGESTS"])
                    #
                    del Index
                #
                del Hashes
                del File_Part

                ## Sort file blocks by number plus start and end offsets for further processing
                File_Blocks = sorted(File_Blocks, key=lambda x: (x["NUMBER"], x["STARTOFS"], x["ENDOFS"]))
                #
                if Debug_Level >= 3:
                    dprint("File Blocks (by number and offsets):")
                    Index = None
                    File_Block = None
                    for Index, File_Block in enumerate(File_Blocks):
                        dprint("{}:".format(Index), File_Block)
                    del File_Block
                    del Index

                ## Display file blocks with hashes (or data) and do verification
                File_Block = None
                for File_Block in File_Blocks:
                    Block_Prefix = "Block #{} {}:".format(File_Block["NUMBER"], File_Block["TYPE"])
                    #
                    if File_Block["TYPE"] == CONST_BLOCK_TYPE.VERIFY:
                        if Arguments.show:
                            print("------------------------------------------------------------")
                            displayBlock(File_Block, block_prefix=Block_Prefix)
                            print("  Type", File_Block["CHECK"])
                            print("  Data", convertBytesToHexString(File_Block["DATA"], sep=""))
                    elif File_Block["TYPE"] == CONST_BLOCK_TYPE.DATA:
                        print("------------------------------------------------------------")
                        displayBlock(File_Block, block_prefix=Block_Prefix)
                        ## Plain hashes (MD5, SHA-1, SHA-256, etc.)
                        for Hash_Key, Hash_Values in CONST_HASHES.items():
                            if not "MODULE" in Hash_Values:
                                continue
                            if not Hash_Key in File_Block["DIGESTS"]:
                                continue
                            #
                            print("  {}:".format(Hash_Key), convertBytesToHexString(File_Block["DIGESTS"][Hash_Key], sep=""))
                        del Hash_Values
                        del Hash_Key
                        ## PKG3 0x40 digest
                        if CONST_HASH_CMAC in File_Block["DIGESTS"] \
                        and 0 in File_Block["DIGESTS"][CONST_HASH_CMAC] \
                        and CONST_HASH_SHA1 in File_Block["DIGESTS"]:
                            print("  Digest CMAC AES Key #{}:".format(0), convertBytesToHexString(File_Block["DIGESTS"][CONST_HASH_CMAC][0], sep=""), " ({})".format(CONST_PKG3_AES_KEYS[0]["DESC"]))
                            print("  Digest SHA-1 (last 8 bytes):", convertBytesToHexString(File_Block["DIGESTS"][CONST_HASH_SHA1][-8:], sep=""))

                        ## CMAC (AES)
                        if CONST_HASH_CMAC in File_Block["DIGESTS"]:
                            print("  CMAC")
                            for Key, Value in File_Block["DIGESTS"][CONST_HASH_CMAC].items():
                                print("    AES Key #{}:".format(Key), convertBytesToHexString(Value, sep=""), " ({})".format(CONST_PKG3_AES_KEYS[Key]["DESC"]))
                            del Value
                            del Key
                        ## HMAC hashes (AES)
                        if CONST_HASH_HMAC in File_Block["DIGESTS"]:
                            for Hash_Key, Hash_Values in File_Block["DIGESTS"][CONST_HASH_HMAC].items():
                                print("  HMAC-{}".format(Hash_Key))
                                for Key, Value in Hash_Values.items():
                                    print("    AES Key #{}:".format(Key), convertBytesToHexString(Value, sep=""), " ({})".format(CONST_PKG3_AES_KEYS[Key]["DESC"]))
                            del Value
                            del Key
                            del Hash_Values
                            del Hash_Key

                        ## Verify hashes and signatures
                        if "VERIFY" in File_Block \
                        and File_Block["VERIFY"]:
                            print("  Verification")
                            Result = None
                            for Verify_Block in File_Block["VERIFY"]:
                                #
                                if Verify_Block["CHECK"] == CONST_HASH_HMAC:
                                    print("NOT NEEDED!")
                                elif Verify_Block["CHECK"] == CONST_HASH_RSA:
                                    Signature_Check = Cryptodome.Signature.pkcs1_15.new(CONST_PKG3_RSA_PUB_KEYS[Verify_Block["KEY"]]["RSA"])
                                    try:
                                        Signature_Check.verify(File_Block["HASHES"][Verify_Block["HASH"]], Verify_Block["DATA"])
                                        Result = True
                                    except ValueError:
                                        Result = False
                                    print("    {}-{} PubKey #{}".format(Verify_Block["CHECK"], Verify_Block["HASH"], Verify_Block["KEY"]), "from offset {:#012x}:".format(Verify_Block["STARTOFS"]), end=" ")
                                    print("OK" if Result else "FAILED!!!")
                                elif Verify_Block["CHECK"] == CONST_HASH_DIGEST:
                                    Result1 = File_Block["DIGESTS"][Verify_Block["HASH"]][Verify_Block["KEY"]] == Verify_Block["DATA"][0:CONST_HASHES[Verify_Block["HASH"]]["SIZE"]]
                                    Result2 = File_Block["DIGESTS"][Verify_Block["HASH2"]][-8:] == Verify_Block["DATA"][-8:]
                                    Result = Result1 and Result2
                                    print("    {}".format(Verify_Block["CHECK"]), "from offset {:#012x}:".format(Verify_Block["STARTOFS"]), end=" ")
                                    print("OK" if Result else "FAILED!!!")
                                    if not (Result1):
                                        print("      {} AES Key #{}:".format(Verify_Block["HASH"], Verify_Block["KEY"]), "OK" if Result1 else "FAILED!!! {}".format(convertBytesToHexString(Verify_Block["DATA"][0:CONST_HASHES[Verify_Block["HASH"]]["SIZE"]], sep="")))
                                    if not (Result2):
                                        print("      {}:".format(Verify_Block["HASH2"]), "OK" if Result2 else "FAILED!!! {}".format(convertBytesToHexString(Verify_Block["DATA"][-8:], sep="")))
                                elif Verify_Block["CHECK"] == CONST_HASH_CMAC:
                                    Result = File_Block["DIGESTS"][CONST_HASH_CMAC][Verify_Block["KEY"]] == Verify_Block["DATA"]
                                    print("    {} AES Key #{}".format(Verify_Block["CHECK"], Verify_Block["KEY"]), "from offset {:#012x}:".format(Verify_Block["STARTOFS"]), end=" ")
                                    print("OK" if Result else "FAILED!!! {}".format(convertBytesToHexString(Verify_Block["DATA"], sep="")))
                                else:
                                    Result = File_Block["DIGESTS"][Verify_Block["CHECK"]] == Verify_Block["DATA"]
                                    print("    {}".format(Verify_Block["CHECK"]), "from offset {:#012x}:".format(Verify_Block["STARTOFS"]), end=" ")
                                    print("OK" if Result else "FAILED!!! {}".format(convertBytesToHexString(Verify_Block["DATA"], sep="")))
                            del Result
                #
                del File_Block
                print("# ------------------------------------------------------------")

                ## Close data stream
                Input_Stream.close(function_debug_level=max(0, Debug_Level))
                del Input_Stream
        sys.stdout.flush()
        sys.stderr.flush()
    except SystemExit:
        raise  ## re-raise/throw up (let Python handle it)
    except:
        print_exc_plus()
