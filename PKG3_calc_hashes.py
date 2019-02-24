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
__version__ = "2019.02.24"
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
import getopt
import re
import traceback
import json
import random
import base64
import xml.etree.ElementTree

import Cryptodome.Cipher.AES
import Cryptodome.Hash


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
    and Version_Check[1] > 6) \
or Version_Check[0] > 3:
    dprint("pycryptodome/x", Cryptodome.__version__, "is good")
    ### https://www.pycryptodome.org/en/latest/src/hash/cmac.html
    def newCMAC(key):
       return Cryptodome.Hash.CMAC.new(key, ciphermod=Cryptodome.Cipher.AES)
    def digestCMAC(self):
       return self.copy().digest()
else:
    dprint("pycryptodome/x < 3.7.2 has an error in CMAC copying, therefore switching to module cryptography for CMAC hashing")
    import cryptography.hazmat.backends
    import cryptography.hazmat.primitives.hashes
    import cryptography.hazmat.primitives.cmac
    import cryptography.hazmat.primitives.ciphers.algorithms
    ### https://cryptography.io/en/latest/hazmat/primitives/mac/cmac/
    def newCMAC(key):
       return cryptography.hazmat.primitives.cmac.CMAC(cryptography.hazmat.primitives.ciphers.algorithms.AES(key), backend=cryptography.hazmat.backends.default_backend())
    def digestCMAC(self):
       return self.copy().finalize()


## Generic Definitions
CONST_READ_SIZE = random.randint(50,100) * 0x100000  ## Read in 50-100 MiB chunks to reduce memory usage and swapping
CONST_READ_AHEAD_SIZE = 128 * 0x400 ## Read first 128 KiB to reduce read requests (fits header of known PS3/PSX/PSP/PSV/PSM packages; Kib/Mib = 0x400/0x100000; biggest header + Items Info found was 2759936 = 0x2a1d00 = ~2.7 MiB)
#
CONST_USER_AGENT_PS3 = "Mozilla/5.0 (PLAYSTATION 3; 4.84)"
#CONST_USER_AGENT_PSP = ""
CONST_USER_AGENT_PSV = " libhttp/3.70 (PS Vita)"
CONST_USER_AGENT_PS4 = "Download/1.00 libhttp/6.20 (PlayStation 4)"

##
## PKG3 Definitions
##
#
## --> Content PKG Keys
## http://www.psdevwiki.com/ps3/Keys#gpkg-key
## https://playstationdev.wiki/psvitadevwiki/index.php?title=Keys#Content_PKG_Keys
CONST_PKG3_CONTENT_KEYS = {
  -1: { "KEY": bytes.fromhex("00000000000000000000000000000000"), "DESC": "Zero key", },
   0: { "KEY": "Lntx18nJoU6jIh8YiCi4+A==", "DESC": "PS3",     },
   1: { "KEY": "B/LGgpC1DSwzgY1wm2DmKw==", "DESC": "PSX/PSP", },
   2: { "KEY": "4xpwyc4d1yvzwGIpY/Lsyw==", "DESC": "PSV",     "DERIVE": True, },
   3: { "KEY": "QjrKOivVZJ+Whqutb9iAHw==", "DESC": "Unknown", "DERIVE": True, },
   4: { "KEY": "rwf9WWUlJ7rxM4lmixfZ6g==", "DESC": "PSM",     "DERIVE": True, },
}
for Key in CONST_PKG3_CONTENT_KEYS:
    if isinstance(CONST_PKG3_CONTENT_KEYS[Key]["KEY"], unicode):
        CONST_PKG3_CONTENT_KEYS[Key]["KEY"] = base64.standard_b64decode(CONST_PKG3_CONTENT_KEYS[Key]["KEY"])
del Key
## --> PKG Update Keys
CONST_PKG3_UPDATE_KEYS = {
   2: { "KEY": "5eJ4qh7jQIKgiCecg/m7yAaCHFLyq10rSr2ZVFA1URQ=", "DESC": "PSV", },
}
for Key in CONST_PKG3_UPDATE_KEYS:
    if isinstance(CONST_PKG3_UPDATE_KEYS[Key]["KEY"], unicode):
        CONST_PKG3_UPDATE_KEYS[Key]["KEY"] = base64.standard_b64decode(CONST_PKG3_UPDATE_KEYS[Key]["KEY"])
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
    def __init__(self, source, func_debug_level=0):
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
                if func_debug_level >= 2:
                    dprint("[INPUT] Opening source as URL XML data stream")
                try:
                    input_stream = requests.get(self._source, headers=self._headers)
                except:
                    eprint("[INPUT] Could not open URL", self._source)
                    eprint("", prefix=None)
                    sys.exit(2)
                xml_root = xml.etree.ElementTree.fromstring(input_stream.text)
                input_stream.close()
            else:
                if func_debug_level >= 2:
                    dprint("[INPUT] Opening source as FILE XML data stream")
                try:
                    input_stream = io.open(self._source, mode="r", buffering=-1, encoding=None, errors=None, newline=None, closefd=True)
                except:
                    eprint("[INPUT] Could not open FILE", self._source)
                    eprint("", prefix=None)
                    sys.exit(2)
                xml_root = xml.etree.ElementTree.fromstring(input_stream.read())
                input_stream.close()
            del input_stream
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
                if func_debug_level >= 2:
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
                if func_debug_level >= 2:
                    dprint("[INPUT] Opening source as URL JSON data stream")
                try:
                    input_stream = requests.get(self._source, headers=self._headers)
                except:
                    eprint("[INPUT] Could not open URL", self._source)
                    eprint("", prefix=None)
                    sys.exit(2)
                json_data = input_stream.json()
                input_stream.close()
            else:
                if func_debug_level >= 2:
                    dprint("[INPUT] Opening source as FILE JSON data stream")
                try:
                    input_stream = io.open(self._source, mode="r", buffering=-1, encoding=None, errors=None, newline=None, closefd=True)
                except:
                    eprint("[INPUT] Could not open FILE", self._source)
                    eprint("", prefix=None)
                    sys.exit(2)
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
                    if func_debug_level >= 2:
                        dprint("[INPUT] Pkg Part #{} Offset {:#012x} Size {} \"{}\"".format(file_part["INDEX"], file_part["START_OFS"], file_part["SIZE"], file_part["url"]))
                del file_part
                del count
            #
            del json_data
        else:
            if self._source.startswith("http:") \
            or self._source.startswith("https:"):
                if func_debug_level >= 2:
                    dprint("[INPUT] Using source as URL PKG data stream")
                self._pkg_name = os.path.basename(requests.utils.urlparse(self._source).path).strip()
            else:
                if func_debug_level >= 2:
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
            if func_debug_level >= 2:
                dprint("[INPUT] Pkg Part #{} Offset {:#012x} \"{}\"".format(file_part["INDEX"], file_part["START_OFS"], file_part["url"]))
            del file_part
            #
            self.open(self._parts[0], func_debug_level=max(0,func_debug_level))
            if "SIZE" in self._parts[0]:
                self._size = self._parts[0]["SIZE"]

        read_size = CONST_READ_AHEAD_SIZE
        if read_size > self._size:
            read_size = self._size
        if read_size > 0:
            self._buffer = self.read(0, read_size, func_debug_level=max(0,func_debug_level))
            self._buffer_size = len(self._buffer)
            if func_debug_level >= 2:
                dprint("[INPUT] Buffered first {} bytes of package".format(self._buffer_size), "(max {})".format(CONST_READ_AHEAD_SIZE) if self._buffer_size != CONST_READ_AHEAD_SIZE else "")

    def getSize(self, func_debug_level=0):
        return self._size

    def getSource(self, func_debug_level=0):
        return self._source

    def getPkgName(self, func_debug_level=0):
        return self._pkg_name

    def open(self, file_part, func_debug_level=0):
        ## Check if already opened
        if "STREAM" in file_part:
            return

        part_size = None
        if file_part["url"].startswith("http:") \
        or file_part["url"].startswith("https:"):
            if func_debug_level >= 3:
                dprint("[INPUT] Opening Pkg Part #{} as URL PKG data stream".format(file_part["INDEX"]))
            ## Persistent session
            ## http://docs.python-requests.org/en/master/api/#request-sessions
            file_part["STREAM_TYPE"] = "requests"
            try:
                file_part["STREAM"] = requests.Session()
            except:
                eprint("[INPUT] Could not create HTTP/S session for PKG URL", file_part["url"])
                eprint("", prefix=None)
                sys.exit(2)
            #
            file_part["STREAM"].headers = self._headers
            response = file_part["STREAM"].head(file_part["url"])
            if func_debug_level >= 3:
                dprint("[INPUT]", response)
                dprint("[INPUT] Response headers:", response.headers)
            if "content-length" in response.headers:
                part_size = int(response.headers["content-length"])
        else:
            if func_debug_level >= 3:
                dprint("[INPUT] Opening Pkg Part #{} as FILE PKG data stream".format(file_part["INDEX"]))
            #
            file_part["STREAM_TYPE"] = "file"
            try:
                file_part["STREAM"] = io.open(file_part["url"], mode="rb", buffering=-1, encoding=None, errors=None, newline=None, closefd=True)
            except:
                eprint("[INPUT] Could not open PKG FILE", file_part["url"])
                eprint("", prefix=None)
                sys.exit(2)
            #
            file_part["STREAM"].seek(0, os.SEEK_END)
            part_size = file_part["STREAM"].tell()

        ## Check file size
        if not part_size is None:
            if not "SIZE" in file_part:
                file_part["SIZE"] = part_size
                file_part["END_OFS"] = file_part["START_OFS"] + file_part["SIZE"]
            else:
                if part_size != file_part["SIZE"]:
                    eprint("[INPUT] File size differs from meta data {} <> {}", part_size, file_part["SIZE"])
                    eprint("", prefix=None)
                    sys.exit(2)

        if func_debug_level >= 3:
            dprint("[INPUT] Data stream is of class", file_part["STREAM"].__class__.__name__)

    def read(self, offset, size, func_debug_level=0):
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
            if func_debug_level >= 3:
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
            if func_debug_level >= 3:
                dprint("[INPUT] Read offset {:#012x} size {}/{} bytes from Pkg Part #{} Offset {:#012x}".format(read_offset, read_buffer_size, size, file_part["INDEX"], file_offset))
            #
            self.open(file_part, func_debug_level=max(0,func_debug_level))
            #
            if file_part["STREAM_TYPE"] == "file":
                file_part["STREAM"].seek(file_offset, os.SEEK_SET)
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
                response = file_part["STREAM"].get(file_part["url"], headers=reqheaders)
                result.extend(response.content)
            #
            read_offset += read_buffer_size
            read_size -= read_buffer_size

        return result

    def close(self, func_debug_level=0):
        for file_part in self._parts:
            if not "STREAM" in file_part:
                continue

            file_part["STREAM"].close()
            del file_part["STREAM"]

        return


def displayBlock(block, print_func=print, **kwargs):
    if "prefix" in kwargs \
    and print_func == print:
        del kwargs["prefix"]
    #
    print_func("Block #{}:".format(block["NUMBER"]), end="", **kwargs)
    #
    if print_func != print:
        kwargs["prefix"] = None
    #
    print_func(" StartOfs {:+#013x}".format(block["STARTOFS"]), end="", **kwargs)
    if "ORGSTARTOFS" in block:
        print_func(" ({})".format(block["ORGSTARTOFS"]), end="", **kwargs)
    #
    if not block["SIZE"] is None:
        print_func(" Size +{}".format(block["SIZE"]), end="", **kwargs)
    #
    if not block["ENDOFS"] is None:
        print_func(" EndOfs {:+#013x}".format(block["ENDOFS"]), end="", **kwargs)
    if "ORGENDOFS" in block:
        print_func(" ({})".format(block["ORGENDOFS"]), end="", **kwargs)
    #
    if not block["VERIFY"] is None:
        print_func(" Verify {}".format(block["VERIFY"]), end="", **kwargs)
    #
    print_func(**kwargs)


def showUsage():
    eprint("Usage: {} [options] <Path or URL to PKG file|value> [<PATH|URL|value> ...]".format(sys.argv[0]), prefix=None)
    eprint("  -h/--help       Show this help", prefix=None)
    eprint("  --values        Non-options parameters are not used as file path or URL.", prefix=None)
    eprint("                  They are used directly as data encoded in UTF-8.", prefix=None)
    eprint("                  Blocks definitions are ignored.", prefix=None)
    eprint("  -b/--block=<startofs>,<+size|[-]endofs>[,<verifyhash:digest|sha-1|none>]", prefix=None)
    eprint("                  Data Block to build hashes for (CMAC, SHA-1, etc.)", prefix=None)
    #eprint("                  Optional verify hash statement to check SHA-1 or CMAC digest", prefix=None)
    #eprint("  --verify        Verify the calculated hashes as defined for each block.", prefix=None)
    eprint("  --extra         Calculate extra hashes. All types with all known keys.", prefix=None)
    eprint("  -d/--debug=<n>  Debug verbosity level", prefix=None)
    eprint("                    0 = No debug info [default]", prefix=None)
    eprint("                    1 = Show calculated file block offsets and sizes", prefix=None)
    eprint("                    2 = Additionally show read actions", prefix=None)
    eprint("                    3 = Additionally show parsed options and internal stuff", prefix=None)


## Global code
if __name__ == "__main__":
    try:
        ## Initialize (global) variables changeable by command line parameters
        ## Global Debug [Verbosity] Level: can be set via '-d'/'--debug='
        Debug_Level = 0
        ##
        Do_Values = False
        Blocks = []
        Extra_Hashes = False
        Show_Usage = False
        Exit_Code = 0

        ## Check parameters from command line
        try:
            Options, Arguments = getopt.gnu_getopt(sys.argv[1:], "hb:d:", ["help", "block=", "debug=", "values", "extra"])
        except getopt.GetoptError as err:
            ## Print help information and exit
            eprint(unicode(err))  ## will print something like "option -X not recognized"
            showUsage()
            sys.exit(2)
        #
        Option = None
        Option_Value = None
        Block_Number = 0
        Block = None
        Block_Count = None
        Skip = None
        Block_StartOfs = None
        Block_Size = None
        Block_EndOfs = None
        for Option, Option_Value in Options:
            if Option in ("-h", "--help"):
                Show_Usage = True
            elif Option in ("-b", "--block"):
                Block_Number += 1
                Block = Option_Value.split(",")
                Block_Count = len(Block)
                if Block_Count < 2 \
                or Block_Count > 3:
                    eprint("Option {} #{}: block value {} is not valid (offset,size[,verifyhash])".format(Option, Block_Number, Option_Value))
                    Exit_Code = 2
                    continue

                Skip = False
                #
                try:
                    Block_StartOfs = int(Block[0], 0)
                except:
                    eprint("Option {} #{}: start offset value {} is not a number".format(Option, Block_Number, Block[0]))
                    Exit_Code = 2
                    Skip = True
                #
                try:
                    if Block[1][0] == "+":
                        Block_Size = int(Block[1], 0)
                        Block_EndOfs = None
                        #
                        if Block_Size <= 0:
                            eprint("Option {} #{}: size value {} is not valid".format(Option, Block_Number, Block_Size))
                            Exit_Code = 2
                            Skip = True
                    else:
                        Block_Size = None
                        Block_EndOfs = int(Block[1], 0)
                except:
                    eprint("Option {} #{}: size/end offset value {} is not a number".format(Option, Block_Number, Block[1]))
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
                            eprint("Option {} #{}: end offset value {} invalid (<= start offset value {})".format(Option, Block_Number, Block_EndOfs, Block_StartOfs))
                            Exit_Code = 2
                            continue
                        #
                        Block_Size = Block_EndOfs - Block_StartOfs
                elif not Block_Size is None:
                    if Block_StartOfs >= 0:
                        Block_EndOfs = Block_StartOfs + Block_Size
                    else:
                        if abs(Block_StartOfs) < Block_Size:
                            eprint("Option {} #{}: size value +{} invalid (> start offset value {})".format(Option, Block_Number, Block_Size, Block_StartOfs))
                            Exit_Code = 2
                            continue

                New_Block = collections.OrderedDict()
                New_Block["NUMBER"] = Block_Number
                New_Block["STARTOFS"] = Block_StartOfs
                New_Block["SIZE"] = Block_Size
                New_Block["ENDOFS"] = Block_EndOfs
                New_Block["VERIFY"] = "DIGEST"
                if Block_Count > 2:
                    if Block[2].lower() == 'sha' \
                    or Block[2].lower() == 'sha1' \
                    or Block[2].lower() == 'sha-1':
                        New_Block["VERIFY"] = "SHA-1"
                    elif Block[2].lower() == 'no' \
                    or Block[2].lower() == 'none':
                        New_Block["VERIFY"] = None
                Blocks.append(New_Block)
                del New_Block
            elif Option in ("-d", "--debug"):
                try:
                    Debug_Level = int(Option_Value)
                    if Debug_Level < 0:
                        eprint("Option {}: value {} is not valid".format(Option, Option_Value))
                        Exit_Code = 2
                except:
                    eprint("Option {}: value {} is not a number".format(Option, Option_Value))
                    Exit_Code = 2
            elif Option in ("--values"):
                Do_Values = True
            elif Option in ("--extra"):
                Extra_Hashes = True
            else:
                eprint("Option {} is unhandled in program".format(Option, Option_Value))
                Exit_Code = 2
        #
        del Block_EndOfs
        del Block_Size
        del Block_StartOfs
        del Skip
        del Block_Count
        del Block
        del Block_Number
        del Option_Value
        del Option

        if not Show_Usage \
        and not Arguments:
            eprint("No", "values" if Do_Values else "paths", "stated")
            Exit_Code = 2
        #
        if not Show_Usage \
        and Exit_Code == 0 \
        and not Do_Values \
        and not Blocks:
            eprint("No blocks stated")
            Exit_Code = 2
        #
        if Show_Usage \
        or Exit_Code:
            showUsage()
            sys.exit(Exit_Code)

        if Debug_Level >= 3:
            dprint("Blocks:")
            Index = None
            for Index in range(len(Blocks)):
                dprint("{}:".format(Index), Blocks[Index])
            del Index

        ## Process paths
        for Source in Arguments:
            if Do_Values:
                ## Process value
                print(">>>>>>>>>> Value:", Source)
                Data_Bytes = Source.encode("UTF-8")
                if Debug_Level >= 2:
                    dprint("Data bytes:", convertBytesToHexString(Data_Bytes, sep=""))

                ## Create hash digests
                Hashes = {}
                ## SHA-1
                Hashes["SHA-1"] = Cryptodome.Hash.SHA1.new(Data_Bytes).digest()
                ## SHA-256
                Hashes["SHA-256"] = Cryptodome.Hash.SHA256.new(Data_Bytes).digest()
                ## MD5
                Hashes["MD5"] = Cryptodome.Hash.MD5.new(Data_Bytes).digest()
                ## CMACs with content keys
                print("  Digest CMAC with Content Keys")
                Hashes["CMAC_CONT"] = collections.OrderedDict()
                for key in CONST_PKG3_CONTENT_KEYS:
                    if Extra_Hashes \
                    or key == 0:  ## Hash for PKG3 Digest CMAC 0x040
                        Hashes["CMAC_CONT"][key] = newCMAC(CONST_PKG3_CONTENT_KEYS[key]["KEY"])
                        Hashes["CMAC_CONT"][key].update(Data_Bytes)
                        Hashes["CMAC_CONT"][key] = Hashes["CMAC_CONT"][key].digest()
                        print("    Key #{}:".format(key), convertBytesToHexString(Hashes["CMAC_CONT"][key], sep=""), " ({})".format(CONST_PKG3_CONTENT_KEYS[key]["DESC"]))
                ## HMACs SHA-1 with content keys
                if Extra_Hashes:
                    print("  Digest HMAC SHA-1 with Content Keys")
                    Hashes["HMAC_SHA1_CONT"] = collections.OrderedDict()
                    for key in CONST_PKG3_CONTENT_KEYS:
                        Hashes["HMAC_SHA1_CONT"][key] = Cryptodome.Hash.HMAC.new(CONST_PKG3_CONTENT_KEYS[key]["KEY"], digestmod=Cryptodome.Hash.SHA1, msg=Data_Bytes).digest()
                        print("    Key #{}:".format(key), convertBytesToHexString(Hashes["HMAC_SHA1_CONT"][key], sep=""), " ({})".format(CONST_PKG3_CONTENT_KEYS[key]["DESC"]))
                ## HMACs SHA-256 with content keys
                if Extra_Hashes:
                    print("  Digest HMAC SHA-256 with Content Keys")
                    Hashes["HMAC_SHA256_CONT"] = collections.OrderedDict()
                    for key in CONST_PKG3_CONTENT_KEYS:
                        Hashes["HMAC_SHA256_CONT"][key] = Cryptodome.Hash.HMAC.new(CONST_PKG3_CONTENT_KEYS[key]["KEY"], digestmod=Cryptodome.Hash.SHA256, msg=Data_Bytes).digest()
                        print("    Key #{}:".format(key), convertBytesToHexString(Hashes["HMAC_SHA256_CONT"][key], sep=""), " ({})".format(CONST_PKG3_CONTENT_KEYS[key]["DESC"]))
                ## HMACs MD5 with content keys
                if Extra_Hashes:
                    print("  Digest HMAC MD5 with Content Keys")
                    Hashes["HMAC_MD5_CONT"] = collections.OrderedDict()
                    for key in CONST_PKG3_CONTENT_KEYS:
                        Hashes["HMAC_MD5_CONT"][key] = Cryptodome.Hash.HMAC.new(CONST_PKG3_CONTENT_KEYS[key]["KEY"], digestmod=Cryptodome.Hash.MD5, msg=Data_Bytes).digest()
                        print("    Key #{}:".format(key), convertBytesToHexString(Hashes["HMAC_MD5_CONT"][key], sep=""), " ({})".format(CONST_PKG3_CONTENT_KEYS[key]["DESC"]))
                ## CMACs with update keys
                if Extra_Hashes:
                    print("  Digest CMAC with Update Keys")
                    Hashes["CMAC_UPD"] = collections.OrderedDict()
                    for key in CONST_PKG3_UPDATE_KEYS:
                        Hashes["CMAC_UPD"][key] = newCMAC(CONST_PKG3_UPDATE_KEYS[key]["KEY"])
                        Hashes["CMAC_UPD"][key].update(Data_Bytes)
                        Hashes["CMAC_UPD"][key] = Hashes["CMAC_UPD"][key].digest()
                        print("    Key #{}:".format(key), convertBytesToHexString(Hashes["CMAC_UPD"][key], sep=""), " ({})".format(CONST_PKG3_UPDATE_KEYS[key]["DESC"]))
                ## HMACs SHA-1 with update keys
                if Extra_Hashes:
                    print("  Digest HMAC SHA-1 with Update Keys")
                    Hashes["HMAC_SHA1_UPD"] = collections.OrderedDict()
                    for key in CONST_PKG3_UPDATE_KEYS:
                        Hashes["HMAC_SHA1_UPD"][key] = Cryptodome.Hash.HMAC.new(CONST_PKG3_UPDATE_KEYS[key]["KEY"], digestmod=Cryptodome.Hash.SHA1, msg=Data_Bytes).digest()
                        print("    Key #{}:".format(key), convertBytesToHexString(Hashes["HMAC_SHA1_UPD"][key], sep=""), " ({})".format(CONST_PKG3_UPDATE_KEYS[key]["DESC"]))
                ## HMACs SHA-256 with update keys
                print("  Digest HMAC SHA-256 with Update Keys")
                Hashes["HMAC_SHA256_UPD"] = collections.OrderedDict()
                for key in CONST_PKG3_UPDATE_KEYS:
                    if Extra_Hashes \
                    or key == 2:  ## Hash for PSV Update URL
                        Hashes["HMAC_SHA256_UPD"][key] = Cryptodome.Hash.HMAC.new(CONST_PKG3_UPDATE_KEYS[key]["KEY"], digestmod=Cryptodome.Hash.SHA256, msg=Data_Bytes).digest()
                        print("    Key #{}:".format(key), convertBytesToHexString(Hashes["HMAC_SHA256_UPD"][key], sep=""), " ({})".format(CONST_PKG3_UPDATE_KEYS[key]["DESC"]))
                ## HMACs MD5 with update keys
                if Extra_Hashes:
                     print("  Digest HMAC MD5 with Update Keys")
                     Hashes["HMAC_MD5_UPD"] = collections.OrderedDict()
                     for key in CONST_PKG3_UPDATE_KEYS:
                         Hashes["HMAC_MD5_UPD"][key] = Cryptodome.Hash.HMAC.new(CONST_PKG3_UPDATE_KEYS[key]["KEY"], digestmod=Cryptodome.Hash.MD5, msg=Data_Bytes).digest()
                         print("    Key #{}:".format(key), convertBytesToHexString(Hashes["HMAC_MD5_UPD"][key], sep=""), " ({})".format(CONST_PKG3_UPDATE_KEYS[key]["DESC"]))
                ## Standard Hashes
                print("  SHA-1:", convertBytesToHexString(Hashes["SHA-1"], sep=""))
                print("  SHA-256:", convertBytesToHexString(Hashes["SHA-256"], sep=""))
                print("  MD5:", convertBytesToHexString(Hashes["MD5"], sep=""))

                del Data_Bytes
            else:
                ## Open PKG source
                print(">>>>>>>>>> PKG Source:", Source)
                Input_Stream = PkgInputReader(Source, func_debug_level=max(0, Debug_Level))
                File_Size = Input_Stream.getSize(func_debug_level=max(0, Debug_Level))
                print("File Size:", File_Size)

                ## Convert blocks to file blocks
                File_Blocks = []
                Block = None
                New_Block = None
                Relative_Offset = None
                Block_Offset = None
                for Block in Blocks:
                    ## Create new file block
                    New_Block = collections.OrderedDict()
                    New_Block["NUMBER"] = Block["NUMBER"]
                    New_Block["STARTOFS"] = Block["STARTOFS"]
                    New_Block["SIZE"] = Block["SIZE"]
                    New_Block["ENDOFS"] = Block["ENDOFS"]
                    New_Block["VERIFY"] = Block["VERIFY"]

                    ## Handle start offset
                    if New_Block["STARTOFS"] < 0:
                        if not File_Size:
                            eprint("Block #{}:".format(New_Block["NUMBER"]), "Skipped as its start offset could not be calculated without a file size", prefix="[WARNING] ")
                            displayBlock(New_Block, print_func=eprint, prefix="[WARNING]  ")
                            continue
                        #
                        Relative_Offset = New_Block["STARTOFS"]
                        Block_Offset = File_Size + Relative_Offset
                        #
                        if Block_Offset < 0:  ## still negative
                            eprint("Block #{}:".format(New_Block["NUMBER"]), "Skipped as its start offset", New_Block["STARTOFS"], "does not fit file size", File_Size, prefix="[WARNING] ")
                            displayBlock(New_Block, print_func=eprint, prefix="[WARNING]  ")
                            continue
                        #
                        New_Block["STARTOFS"] = Block_Offset
                        New_Block["ORGSTARTOFS"] = Relative_Offset
                    #
                    if File_Size \
                    and New_Block["STARTOFS"] >= File_Size:
                        eprint("Block #{}:".format(New_Block["NUMBER"]), "Skipped as its start offset", New_Block["STARTOFS"], "does not fit file size", File_Size, prefix="[WARNING] ")
                        displayBlock(New_Block, print_func=eprint, prefix="[WARNING]  ")
                        continue

                    ## Handle end offset
                    if New_Block["ENDOFS"] is None:
                        New_Block["ENDOFS"] = New_Block["STARTOFS"] + New_Block["SIZE"]
                    elif New_Block["ENDOFS"] <= 0:
                        if not File_Size:
                            eprint("Block #{}:".format(New_Block["NUMBER"]), "Skipped as its end offset could not be calculated without a file size", prefix="[WARNING] ")
                            displayBlock(New_Block, print_func=eprint, prefix="[WARNING]  ")
                            continue
                        #
                        Relative_Offset = New_Block["ENDOFS"]
                        Block_Offset = File_Size + Relative_Offset
                        #
                        if Block_Offset < 0:  ## still negative
                            eprint("Block #{}:".format(New_Block["NUMBER"]), "Skipped as its end offset", New_Block["ENDOFS"], "does not fit file size", File_Size, prefix="[WARNING] ")
                            displayBlock(New_Block, print_func=eprint, prefix="[WARNING]  ")
                            continue
                        #
                        New_Block["ENDOFS"] = Block_Offset
                        New_Block["ORGENDOFS"] = Relative_Offset
                    #
                    if File_Size \
                    and New_Block["ENDOFS"] > File_Size:
                        eprint("Block #{}:".format(New_Block["NUMBER"]), "Skipped as its end offset", New_Block["ENDOFS"], "does not fit file size", File_Size, prefix="[WARNING] ")
                        displayBlock(New_Block, print_func=eprint, prefix="[WARNING]  ")
                        continue

                    ## Handle size
                    if New_Block["SIZE"] is None:
                        New_Block["SIZE"] = New_Block["ENDOFS"] - New_Block["STARTOFS"]
                    #
                    if New_Block["SIZE"] <= 0:
                        eprint("Block #{}:".format(New_Block["NUMBER"]), "Skipped as its size", New_Block["SIZE"], "is invalid (<=0)", prefix="[WARNING] ")
                        displayBlock(New_Block, print_func=eprint, prefix="[WARNING]  ")
                        continue

                    ## Add file block to process list
                    File_Blocks.append(New_Block)
                #
                del Block_Offset
                del Relative_Offset
                del New_Block
                del Block

                ## Sort file blocks by calculated offsets and sizes
                File_Blocks = sorted(File_Blocks, key=lambda x: (x["STARTOFS"], x["ENDOFS"]))
                #
                if Debug_Level >= 1:
                    dprint("File Blocks (by offsets):")
                    Index = None
                    for Index in range(len(File_Blocks)):
                        dprint("{}:".format(Index), File_Blocks[Index])
                    del Index

                ## Calculate file parts out of file blocks
                File_Parts = []
                File_Part_Index = -1
                Block = None
                for Block in File_Blocks:
                    ## File block starts a new file part
                    if File_Part_Index < 0 \
                    or Block["STARTOFS"] >= File_Parts[File_Part_Index]["ENDOFS"]:
                        File_Part_Index = len(File_Parts)
                        #
                        New_Part = collections.OrderedDict()
                        New_Part["STARTOFS"] = Block["STARTOFS"]
                        New_Part["ENDOFS"] = Block["ENDOFS"]
                        New_Part["OFFSETS"] = []
                        File_Parts.append(New_Part)
                        del New_Part
                    ## Block extends current file part
                    elif Block["ENDOFS"] > File_Parts[File_Part_Index]["ENDOFS"]:
                        File_Parts[File_Part_Index]["ENDOFS"] = Block["ENDOFS"]

                    ## Collect offsets
                    File_Parts[File_Part_Index]["OFFSETS"].extend((Block["STARTOFS"], Block["ENDOFS"]))
                del Block
                del File_Part_Index

                ## For each file part do a unique sort of its offsets
                File_Part = None
                for File_Part in File_Parts:
                    File_Part["OFFSETS"] = sorted(set(File_Part["OFFSETS"]))
                del File_Part
                #
                if Debug_Level >= 1:
                    dprint("File Parts:")
                    Index = None
                    for Index in range(len(File_Parts)):
                        dprint("{}:".format(Index), File_Parts[Index])
                    del Index

                ## Read each file part in chunks derived from the offsets
                ## and calculate the CMAC and SHA hashes for each file block
                ## For definition see http://www.psdevwiki.com/ps3/PKG_files#0x40_digest
                Block_Count = len(File_Blocks)
                for _i in range(len(File_Parts)):
                    Hashes = {}
                    for _j in range(len(File_Parts[_i]["OFFSETS"])-1):
                        ## Determine offset values
                        Block_Offset = File_Parts[_i]["OFFSETS"][_j]
                        Next_Offset = File_Parts[_i]["OFFSETS"][_j+1]
                        Block_Size = Next_Offset - Block_Offset

                        ## Add hashes entry for new offset
                        Hashes[Block_Offset] = {}
                        ## SHA-1
                        Hashes[Block_Offset]["SHA-1"] = Cryptodome.Hash.SHA1.new()
                        ## SHA-256
                        Hashes[Block_Offset]["SHA-256"] = Cryptodome.Hash.SHA256.new()
                        ## MD5
                        Hashes[Block_Offset]["MD5"] = Cryptodome.Hash.MD5.new()
                        ## CMACs with content keys
                        Hashes[Block_Offset]["CMAC_CONT"] = collections.OrderedDict()
                        for key in CONST_PKG3_CONTENT_KEYS:
                            if Extra_Hashes \
                            or key == 0:  ## Hash for PKG3 Digest CMAC 0x040
                                Hashes[Block_Offset]["CMAC_CONT"][key] = newCMAC(CONST_PKG3_CONTENT_KEYS[key]["KEY"])
                        ## HMACs SHA-1 with content keys
                        if Extra_Hashes:
                            Hashes[Block_Offset]["HMAC_SHA1_CONT"] = collections.OrderedDict()
                            for key in CONST_PKG3_CONTENT_KEYS:
                                Hashes[Block_Offset]["HMAC_SHA1_CONT"][key] = Cryptodome.Hash.HMAC.new(CONST_PKG3_CONTENT_KEYS[key]["KEY"], digestmod=Cryptodome.Hash.SHA1)
                        ## HMACs SHA-256 with content keys
                        if Extra_Hashes:
                            Hashes[Block_Offset]["HMAC_SHA256_CONT"] = collections.OrderedDict()
                            for key in CONST_PKG3_CONTENT_KEYS:
                                Hashes[Block_Offset]["HMAC_SHA256_CONT"][key] = Cryptodome.Hash.HMAC.new(CONST_PKG3_CONTENT_KEYS[key]["KEY"], digestmod=Cryptodome.Hash.SHA256)
                        ## HMACs MD5 with content keys
                        if Extra_Hashes:
                            Hashes[Block_Offset]["HMAC_MD5_CONT"] = collections.OrderedDict()
                            for key in CONST_PKG3_CONTENT_KEYS:
                                Hashes[Block_Offset]["HMAC_MD5_CONT"][key] = Cryptodome.Hash.HMAC.new(CONST_PKG3_CONTENT_KEYS[key]["KEY"], digestmod=Cryptodome.Hash.MD5)
                        ## CMACs with update keys
                        if Extra_Hashes:
                            Hashes[Block_Offset]["CMAC_UPD"] = collections.OrderedDict()
                            for key in CONST_PKG3_UPDATE_KEYS:
                                Hashes[Block_Offset]["CMAC_UPD"][key] = newCMAC(CONST_PKG3_UPDATE_KEYS[key]["KEY"])
                        ## HMACs SHA-1 with update keys
                        if Extra_Hashes:
                            Hashes[Block_Offset]["HMAC_SHA1_UPD"] = collections.OrderedDict()
                            for key in CONST_PKG3_UPDATE_KEYS:
                                Hashes[Block_Offset]["HMAC_SHA1_UPD"][key] = Cryptodome.Hash.HMAC.new(CONST_PKG3_UPDATE_KEYS[key]["KEY"], digestmod=Cryptodome.Hash.SHA1)
                        ## HMACs SHA-256 with update keys
                        if Extra_Hashes:
                            Hashes[Block_Offset]["HMAC_SHA256_UPD"] = collections.OrderedDict()
                            for key in CONST_PKG3_UPDATE_KEYS:
                                Hashes[Block_Offset]["HMAC_SHA256_UPD"][key] = Cryptodome.Hash.HMAC.new(CONST_PKG3_UPDATE_KEYS[key]["KEY"], digestmod=Cryptodome.Hash.SHA256)
                        ## HMACs MD5 with update keys
                        if Extra_Hashes:
                            Hashes[Block_Offset]["HMAC_MD5_UPD"] = collections.OrderedDict()
                            for key in CONST_PKG3_UPDATE_KEYS:
                                Hashes[Block_Offset]["HMAC_MD5_UPD"][key] = Cryptodome.Hash.HMAC.new(CONST_PKG3_UPDATE_KEYS[key]["KEY"], digestmod=Cryptodome.Hash.MD5)

                        ## Get data from file
                        if Debug_Level >= 2:
                            dprint("Retrieve offset {:#010x} size {}".format(Block_Offset, Block_Size))
                        Data_Bytes = None
                        while Block_Size > 0:
                            if Block_Size > CONST_READ_SIZE:
                                Size = CONST_READ_SIZE
                            else:
                                Size = Block_Size
                            if Debug_Level >= 3:
                                dprint("...offset {:#010x} size {}".format(Block_Offset, Size))
                            Data_Bytes = Input_Stream.read(Block_Offset, Size, func_debug_level=max(0, Debug_Level))
                            Block_Size -= Size
                            Block_Offset += Size

                            ## Update hashes with data
                            for _k in Hashes:
                                ## SHA-1
                                Hashes[_k]["SHA-1"].update(Data_Bytes)
                                ## SHA-256
                                Hashes[_k]["SHA-256"].update(Data_Bytes)
                                ## MD5
                                Hashes[_k]["MD5"].update(Data_Bytes)
                                ## CMACs with content keys
                                if "CMAC_CONT" in Hashes[_k]:
                                    for key in Hashes[_k]["CMAC_CONT"]:
                                        Hashes[_k]["CMAC_CONT"][key].update(Data_Bytes)
                                ## HMACs SHA-1 with content keys
                                if "HMAC_SHA1_CONT" in Hashes[_k]:
                                    for key in Hashes[_k]["HMAC_SHA1_CONT"]:
                                        Hashes[_k]["HMAC_SHA1_CONT"][key].update(Data_Bytes)
                                ## HMACs SHA-256 with content keys
                                if "HMAC_SHA256_CONT" in Hashes[_k]:
                                    for key in Hashes[_k]["HMAC_SHA256_CONT"]:
                                        Hashes[_k]["HMAC_SHA256_CONT"][key].update(Data_Bytes)
                                ## HMACs MD5 with content keys
                                if "HMAC_MD5_CONT" in Hashes[_k]:
                                    for key in Hashes[_k]["HMAC_MD5_CONT"]:
                                        Hashes[_k]["HMAC_MD5_CONT"][key].update(Data_Bytes)
                                ## CMACs with update keys
                                if "CMAC_UPD" in Hashes[_k]:
                                    for key in Hashes[_k]["CMAC_UPD"]:
                                        Hashes[_k]["CMAC_UPD"][key].update(Data_Bytes)
                                ## HMACs SHA-1 with update keys
                                if "HMAC_SHA1_UPD" in Hashes[_k]:
                                    for key in Hashes[_k]["HMAC_SHA1_UPD"]:
                                        Hashes[_k]["HMAC_SHA1_UPD"][key].update(Data_Bytes)
                                ## HMACs SHA-256 with update keys
                                if "HMAC_SHA256_UPD" in Hashes[_k]:
                                    for key in Hashes[_k]["HMAC_SHA256_UPD"]:
                                        Hashes[_k]["HMAC_SHA256_UPD"][key].update(Data_Bytes)
                                ## HMACs MD5 with update keys
                                if "HMAC_MD5_UPD" in Hashes[_k]:
                                    for key in Hashes[_k]["HMAC_MD5_UPD"]:
                                        Hashes[_k]["HMAC_MD5_UPD"][key].update(Data_Bytes)
                        del Data_Bytes

                        ## Check if any file block got completed
                        for _k in range(Block_Count):
                            if File_Blocks[_k]["ENDOFS"] == Next_Offset:
                                if Debug_Level >= 2:
                                    dprint("Block #{} completed".format(File_Blocks[_k]["NUMBER"]))
                                Block_Offset = File_Blocks[_k]["STARTOFS"]
                                ## SHA-1
                                File_Blocks[_k]["SHA-1"] = Hashes[Block_Offset]["SHA-1"].copy().digest()
                                ## SHA-256
                                File_Blocks[_k]["SHA-256"] = Hashes[Block_Offset]["SHA-256"].copy().digest()
                                ## MD5
                                File_Blocks[_k]["MD5"] = Hashes[Block_Offset]["MD5"].copy().digest()
                                ## CMACs with content keys
                                if "CMAC_CONT" in Hashes[Block_Offset]:
                                    File_Blocks[_k]["CMAC_CONT"] = collections.OrderedDict()
                                    for key in Hashes[Block_Offset]["CMAC_CONT"]:
                                        File_Blocks[_k]["CMAC_CONT"][key] = digestCMAC(Hashes[Block_Offset]["CMAC_CONT"][key])
                                ## HMACs SHA-1 with content keys
                                if "HMAC_SHA1_CONT" in Hashes[Block_Offset]:
                                    File_Blocks[_k]["HMAC_SHA1_CONT"] = collections.OrderedDict()
                                    for key in Hashes[Block_Offset]["HMAC_SHA1_CONT"]:
                                        File_Blocks[_k]["HMAC_SHA1_CONT"][key] = digestCMAC(Hashes[Block_Offset]["HMAC_SHA1_CONT"][key])
                                ## HMACs SHA-256 with content keys
                                if "HMAC_SHA256_CONT" in Hashes[Block_Offset]:
                                    File_Blocks[_k]["HMAC_SHA256_CONT"] = collections.OrderedDict()
                                    for key in Hashes[Block_Offset]["HMAC_SHA256_CONT"]:
                                        File_Blocks[_k]["HMAC_SHA256_CONT"][key] = digestCMAC(Hashes[Block_Offset]["HMAC_SHA256_CONT"][key])
                                ## HMACs MD5 with content keys
                                if "HMAC_MD5_CONT" in Hashes[Block_Offset]:
                                    File_Blocks[_k]["HMAC_MD5_CONT"] = collections.OrderedDict()
                                    for key in Hashes[Block_Offset]["HMAC_MD5_CONT"]:
                                        File_Blocks[_k]["HMAC_MD5_CONT"][key] = digestCMAC(Hashes[Block_Offset]["HMAC_MD5_CONT"][key])
                                ## CMACs with update keys
                                if "CMAC_UPD" in Hashes[Block_Offset]:
                                    File_Blocks[_k]["CMAC_UPD"] = collections.OrderedDict()
                                    for key in Hashes[Block_Offset]["CMAC_UPD"]:
                                        File_Blocks[_k]["CMAC_UPD"][key] = digestCMAC(Hashes[Block_Offset]["CMAC_UPD"][key])
                                ## HMACs SHA-1 with update keys
                                if "HMAC_SHA1_UPD" in Hashes[Block_Offset]:
                                    File_Blocks[_k]["HMAC_SHA1_UPD"] = collections.OrderedDict()
                                    for key in Hashes[Block_Offset]["HMAC_SHA1_UPD"]:
                                        File_Blocks[_k]["HMAC_SHA1_UPD"][key] = digestCMAC(Hashes[Block_Offset]["HMAC_SHA1_UPD"][key])
                                ## HMACs SHA-256 with update keys
                                if "HMAC_SHA256_UPD" in Hashes[Block_Offset]:
                                    File_Blocks[_k]["HMAC_SHA256_UPD"] = collections.OrderedDict()
                                    for key in Hashes[Block_Offset]["HMAC_SHA256_UPD"]:
                                        File_Blocks[_k]["HMAC_SHA256_UPD"][key] = digestCMAC(Hashes[Block_Offset]["HMAC_SHA256_UPD"][key])
                                ## HMACs MD5 with update keys
                                if "HMAC_MD5_UPD" in Hashes[Block_Offset]:
                                    File_Blocks[_k]["HMAC_MD5_UPD"] = collections.OrderedDict()
                                    for key in Hashes[Block_Offset]["HMAC_MD5_UPD"]:
                                        File_Blocks[_k]["HMAC_MD5_UPD"][key] = digestCMAC(Hashes[Block_Offset]["HMAC_MD5_UPD"][key])

                File_Blocks = sorted(File_Blocks, key=lambda x: (x["NUMBER"]))

                for _i in range(Block_Count):
                    print("Block #{} offset {:#010x} size {}{}{}".format(File_Blocks[_i]["NUMBER"], File_Blocks[_i]["STARTOFS"], File_Blocks[_i]["SIZE"], " ({})".format(File_Blocks[_i]["ORGSIZE"]) if "ORGSIZE" in File_Blocks[_i] else "", " (verify {})".format(File_Blocks[_i]["VERIFY"]) if File_Blocks[_i]["VERIFY"] != "DIGEST" else ""))

                    print("  Digest CMAC:", convertBytesToHexString(File_Blocks[_i]["CMAC_CONT"][0], sep=""), " ({})".format(CONST_PKG3_CONTENT_KEYS[0]["DESC"]))
                    print("  Digest SHA-1 (last 8 bytes):", convertBytesToHexString(File_Blocks[_i]["SHA-1"][-8:], sep=""))
                    print("  SHA-1:", convertBytesToHexString(File_Blocks[_i]["SHA-1"], sep=""))
                    print("  SHA-256:", convertBytesToHexString(File_Blocks[_i]["SHA-256"], sep=""))
                    print("  MD5:", convertBytesToHexString(File_Blocks[_i]["MD5"], sep=""))

                    ## Display extra hashes
                    ## CMACs with content keys
                    if "CMAC_CONT" in File_Blocks[_i] \
                    and Extra_Hashes:
                        print("  Digest CMAC with Content Keys")
                        for key in File_Blocks[_i]["CMAC_CONT"]:
                            if key != 0:
                                print("    Key #{}:".format(key), convertBytesToHexString(File_Blocks[_i]["CMAC_CONT"][key], sep=""), " ({})".format(CONST_PKG3_CONTENT_KEYS[key]["DESC"]))
                    ## HMACs SHA-1 with content keys
                    if "HMAC_SHA1_CONT" in File_Blocks[_i]:
                        print("  Digest HMAC SHA-1 with Content Keys")
                        for key in File_Blocks[_i]["HMAC_SHA1_CONT"]:
                            print("    Key #{}:".format(key), convertBytesToHexString(File_Blocks[_i]["HMAC_SHA1_CONT"][key], sep=""), " ({})".format(CONST_PKG3_CONTENT_KEYS[key]["DESC"]))
                    ## HMACs SHA-256 with content keys
                    if "HMAC_SHA256_CONT" in File_Blocks[_i]:
                        print("  Digest HMAC SHA-256 with Content Keys")
                        for key in File_Blocks[_i]["HMAC_SHA256_CONT"]:
                            print("    Key #{}:".format(key), convertBytesToHexString(File_Blocks[_i]["HMAC_SHA256_CONT"][key], sep=""), " ({})".format(CONST_PKG3_CONTENT_KEYS[key]["DESC"]))
                    ## HMACs MD5 with content keys
                    if "HMAC_MD5_CONT" in File_Blocks[_i]:
                        print("  Digest HMAC MD5 with Content Keys")
                        for key in File_Blocks[_i]["HMAC_MD5_CONT"]:
                            print("    Key #{}:".format(key), convertBytesToHexString(File_Blocks[_i]["HMAC_MD5_CONT"][key], sep=""), " ({})".format(CONST_PKG3_CONTENT_KEYS[key]["DESC"]))
                    ## CMACs with update keys
                    if "CMAC_UPD" in File_Blocks[_i] \
                    and Extra_Hashes:
                        print("  Digest CMAC with Update Keys")
                        for key in File_Blocks[_i]["CMAC_UPD"]:
                            print("    Key #{}:".format(key), convertBytesToHexString(File_Blocks[_i]["CMAC_UPD"][key], sep=""), " ({})".format(CONST_PKG3_UPDATE_KEYS[key]["DESC"]))
                    ## HMACs SHA-1 with update keys
                    if "HMAC_SHA1_UPD" in File_Blocks[_i]:
                        print("  Digest HMAC SHA-1 with Update Keys")
                        for key in File_Blocks[_i]["HMAC_SHA1_UPD"]:
                            print("    Key #{}:".format(key), convertBytesToHexString(File_Blocks[_i]["HMAC_SHA1_UPD"][key], sep=""), " ({})".format(CONST_PKG3_UPDATE_KEYS[key]["DESC"]))
                    ## HMACs SHA-256 with update keys
                    if "HMAC_SHA256_UPD" in File_Blocks[_i]:
                        print("  Digest HMAC SHA-256 with Update Keys")
                        for key in File_Blocks[_i]["HMAC_SHA256_UPD"]:
                            print("    Key #{}:".format(key), convertBytesToHexString(File_Blocks[_i]["HMAC_SHA256_UPD"][key], sep=""), " ({})".format(CONST_PKG3_UPDATE_KEYS[key]["DESC"]))
                    ## HMACs MD5 with update keys
                    if "HMAC_MD5_UPD" in File_Blocks[_i]:
                        print("  Digest HMAC MD5 with Update Keys")
                        for key in File_Blocks[_i]["HMAC_MD5_UPD"]:
                            print("    Key #{}:".format(key), convertBytesToHexString(File_Blocks[_i]["HMAC_MD5_UPD"][key], sep=""), " ({})".format(CONST_PKG3_UPDATE_KEYS[key]["DESC"]))

                ## Close data stream
                Input_Stream.close(func_debug_level=max(0, Debug_Level))
                del Input_Stream
        sys.stdout.flush()
        sys.stderr.flush()
    except SystemExit:
        raise  ## re-raise/throw up (let Python handle it)
    except:
        print_exc_plus()
