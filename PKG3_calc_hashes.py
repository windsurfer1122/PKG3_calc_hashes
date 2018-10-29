#!/usr/bin/env python3
# -*- coding: utf-8 -*-
### ^^^ see https://www.python.org/dev/peps/pep-0263/

###
### PKG3_calc_hashes.py by "windsurfer1122" (c) 2018
### Calculate hashes for data blocks inside PS3/PSX/PSP/PSV/PSM packages.
###
### Goals:
### * Build CMAC and SHA-1/256 hashes of data, just like it is used in the 0x40 digest of PKG3 packages (PS3/PSX/PSP/PSV/PSM)
###   For definition see http://www.psdevwiki.com/ps3/PKG_files#0x40_digest
### * Support of all known package types: PS3/PSX/PSP, PSV/PSM
### * Easy to maintain and no compiler necessary (=interpreter language)
### * Cross platform support
###   * Decision: Python 3
###     * Compatible with Python 2 (target version 2.7)
###       * Identical output
###       * Forward-compatible solutions preferred
###
### For options execute: PKG3_calc_hashes.py -h and read the README.md
### Use at your own risk!
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
###
### git master repository at https://github.com/windsurfer1122
###

###
### Python Related Information
###
### Using a HTTP Proxy: export HTTP_PROXY="http://192.168.0.1:3128"; export HTTPS_PROXY="http://192.168.0.1:1080";
###
### Python 3 on Debian:
### May need to install apt packages python3-crypto python3-cryptography, as Python 2 is default on Debian as of version 8
###
### Workarounds for Python 2 (see: http://python-future.org/compatible_idioms.html)
### - convert byte string of struct.pack() to bytes
### - use future print function
### - use future unicode literals
###
### Python 2 on Debian:
### May need to install apt package python-future python-crypto python-cryptography, as Python 2 is default on Debian as of version 8
###
### Adopted PEP8 Coding Style:
### * [joined_]lower for attributes, variables
### * ALL_CAPS for constants
### * StudlyCaps for classes
### * (differs to PEP8) mixedCase for functions, methods
### * (differs to PEP8) StudlyCaps global variables
###

### Python 2 workarounds:
## a) prevent interpreting print(a,b) as a tuple plus support print(a, file=sys.stderr)
from __future__ import print_function
## b) interpret all literals as unicode
from __future__ import unicode_literals
## c) same division handling ( / = float, // = integer)
from __future__ import division
## d) interpret long as int
from builtins import int
## e) support bytes()
from builtins import bytes

import sys
import struct
import io
import requests
import collections
import locale
import os
import getopt
import hmac
import hashlib
import random

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms


## Debug level for structure initializations (will be reset in "main" code)
DebugLevel = 0


## Error and Debug print to stderr
## https://stackoverflow.com/questions/5574702/how-to-print-to-stderr-in-python
def eprint(*args, **kwargs):  ## error print
    print(*args, file=sys.stderr, **kwargs)

def dprint(*args, **kwargs):  ## debug print
    if DebugLevel:
        print("[debug]", *args, file=sys.stderr, **kwargs)


## Python 2 workaround: set system default encoding to UTF-8 like in Python 3
## All results will be Unicode and we want all output to be UTF-8
if sys.getdefaultencoding().lower() != "utf-8":
    if DebugLevel >= 1:
        eprint("Default Encoding set from {} to UTF-8".format(sys.getdefaultencoding()))
    reload(sys)
    sys.setdefaultencoding("utf-8")

## General debug information related to Python and Unicode
if DebugLevel >= 1:
    ## List encodings
    dprint("Python Version {}".format(sys.version))
    dprint("DEFAULT Encoding {}".format(sys.getdefaultencoding()))
    dprint("LOCALE Encoding {}".format(locale.getpreferredencoding()))
    dprint("STDOUT Encoding {} Terminal {}".format(sys.stdout.encoding, sys.stdout.isatty()))
    dprint("STDERR Encoding {} Terminal {}".format(sys.stderr.encoding, sys.stderr.isatty()))
    dprint("FILESYS Encoding {}".format(sys.getfilesystemencoding()))
    value = ""
    if "PYTHONIOENCODING" in os.environ:
        value = os.environ["PYTHONIOENCODING"]
    dprint("PYTHONIOENCODING={}".format(value))
    ## Check Unicode
    dprint("ö ☺ ☻")

## Python 2/3 workaround: define unicode for Python 3 like in Python 2
## Unfortunately a backward-compatible workaround, as I couldn't find a forward-compatible one :(
## Every string is Unicode
## https://stackoverflow.com/questions/34803467/unexpected-exception-name-basestring-is-not-defined-when-invoking-ansible2
try:
    unicode
except:
    if DebugLevel >= 1:
        eprint("Define \"unicode = str\" for Python 3 :(")
    unicode = str


##
## Generic Definitions
##
#
CONST_READ_SIZE = random.randint(10,100) * 0x100000  ## Read in 10-100 MiB chunks to reduce memory usage

##
## PKG3 Definitions
##
#
## --> Content PKG Keys
## http://www.psdevwiki.com/ps3/Keys#gpkg-key
## https://playstationdev.wiki/psvitadevwiki/index.php?title=Keys#Content_PKG_Keys
CONST_PKG3_CONTENT_KEYS = {
   0: { "KEY": bytes.fromhex("2e7b71d7c9c9a14ea3221f188828b8f8"), "DESC": "PS3",     },
   1: { "KEY": bytes.fromhex("07f2c68290b50d2c33818d709b60e62b"), "DESC": "PSX/PSP", },
   2: { "KEY": bytes.fromhex("e31a70c9ce1dd72bf3c0622963f2eccb"), "DESC": "PSV",     "DERIVE": True, },
   3: { "KEY": bytes.fromhex("423aca3a2bd5649f9686abad6fd8801f"), "DESC": "Unknown", "DERIVE": True, },
   4: { "KEY": bytes.fromhex("af07fd59652527baf13389668b17d9ea"), "DESC": "PSM",     "DERIVE": True, },
}


class PkgReader():
    def __init__(self, source, debug_level=0):
        self._source = source
        self._size = None

        if self._source.startswith("http:") \
        or self._source.startswith("https:"):
            if debug_level >= 2:
                dprint("Opening source as URL data stream")
            self._stream_type = "requests"
            ## Persistent session
            ## http://docs.python-requests.org/en/master/api/#request-sessions
            try:
                self._data_stream = requests.Session()
            except:
                eprint("\nERROR: {}: Could not create HTTP/S session for PKG URL".format(sys.argv[0]))
                sys.exit(2)
            self._data_stream.headers = {"User-Agent": "libhttp/3.69 (PS Vita)"}
            response = self._data_stream.head(self._source)
            if debug_level >= 2:
                dprint(response)
                dprint("Response headers:", response.headers)
            if "content-length" in response.headers:
                self._size = int(response.headers["content-length"])
        else:
            if debug_level >= 2:
                dprint("Opening source as FILE data stream")
            self._stream_type = "file"
            try:
                self._data_stream = io.open(self._source, mode="rb", buffering=-1, encoding=None, errors=None, newline=None, closefd=True)
            except:
                eprint("\nERROR: {}: Could not open PKG FILE {}".format(sys.argv[0], self._source))
                sys.exit(2)
            #
            self._data_stream.seek(0, os.SEEK_END)
            self._size = self._data_stream.tell()

        if debug_level >= 3:
            dprint("Data stream is of class {}".format(self._data_stream.__class__.__name__))

    def getSize(self, debug_level=0):
        return self._size

    def read(self, offset, size, debug_level=0):
        if self._stream_type == "file":
            self._data_stream.seek(offset, os.SEEK_SET)
            return self._data_stream.read(size)
        elif self._stream_type == "requests":
            ## Send request in persistent session
            ## http://docs.python-requests.org/en/master/api/#requests.Session.get
            ## http://docs.python-requests.org/en/master/api/#requests.request
            reqheaders={"Range": "bytes={}-{}".format(offset, offset + size - 1)}
            response = self._data_stream.get(self._source, headers=reqheaders)
            return response.content

    def close(self, debug_level=0):
        return self._data_stream.close()


def convertBytesToHexString(data, format=""):
    if isinstance(data, int):
        data = struct.pack(format, data)
    ## Python 2 workaround: convert str to bytes
    if isinstance(data, str):
        data = bytes(data)
    #
    return " ".join(["%02x" % b for b in data])


def showUsage():
    eprint("Usage: {} [options] <URL of or path to PKG file> [<URL|PATH> ...]".format(sys.argv[0]))
    eprint("  -h/--help       Show this help")
    eprint("  -d/--debug=<n>  Debug verbosity level")
    eprint("                    0 = No debug info [default]")
    eprint("                    1 = Show calculated file block offsets and sizes")
    eprint("                    2 = Additionally show read actions")
    eprint("                    3 = Additionally show parsed options and internal stuff")
    eprint("  -b/--block=<offset>,<size>[,<verifyhash:sha-1|none>]")
    eprint("                  Data Block to build hashes for (CMAC, SHA-1, etc.)")
    eprint("                  Optional verify hash statement sha-1 will check SHA-1 instead")
    eprint("                  of CMAC digest, e.g. file hash at the end of each pkg file")


## Global code
if __name__ == "__main__":
    ## Initialize (global) variables changeable by command line parameters
    ## Global Debug [Verbosity] Level: can be set via '-d'/'--debug='
    DebugLevel = 0
    ## Output Format: can be set via '-f'/'--format='
    Blocks = []
    ShowUsage = False
    ExitCode = 0

    ## Check parameters from command line
    try:
        Options, Arguments = getopt.gnu_getopt(sys.argv[1:], "hb:d:", ["help", "block=", "debug="])
    except getopt.GetoptError as err:
        ## Print help information and exit
        eprint(unicode(err))  ## will print something like "option -X not recognized"
        showUsage()
        sys.exit(2)
    #
    for Option, OptionValue in Options:
        if Option in ("-h", "--help"):
            ShowUsage = True
        elif Option in ("-b", "--block"):
            Block = OptionValue.split(",")
            BlockCount = len(Block)
            if BlockCount < 2 \
            or BlockCount > 3:
                eprint("Option {}: block value {} is not valid (offset,size[,verifyhash])".format(Option, OptionValue))
                ExitCode = 2
                continue

            Skip = False
            try:
                BlockOffset = int(Block[0])
                if BlockOffset < 0:
                    eprint("Option {}: offset value {} is not valid".format(Option, BlockOffset))
                    ExitCode = 2
                    Skip = True
            except:
                eprint("Option {}: offset value {} is not a number".format(Option, Block[0]))
                ExitCode = 2
                Skip = True
            try:
                BlockSize = int(Block[1])
            except:
                eprint("Option {}: size value {} is not a number".format(Option, Block[1]))
                ExitCode = 2
                Skip = True

            if Skip:
                continue

            Index = len(Blocks)
            Blocks.append({})
            Blocks[Index]["NUMBER"] = Index + 1
            Blocks[Index]["OFFSET"] = BlockOffset
            Blocks[Index]["SIZE"] = BlockSize
            Blocks[Index]["VERIFY"] = "DIGEST"
            if BlockCount > 2:
                if Block[2].lower() == 'sha' \
                or Block[2].lower() == 'sha1' \
                or Block[2].lower() == 'sha-1':
                    Blocks[Index]["VERIFY"] = "SHA-1"
                elif Block[2].lower() == 'no' \
                or Block[2].lower() == 'none':
                    Blocks[Index]["VERIFY"] = None
        elif Option in ("-d", "--debug"):
            try:
                DebugLevel = int(OptionValue)
                if DebugLevel < 0:
                    eprint("Option {}: value {} is not valid".format(Option, OptionValue))
                    ExitCode = 2
            except:
                eprint("Option {}: value {} is not a number".format(Option, OptionValue))
                ExitCode = 2
        else:
            eprint("Option {} is unhandled in program".format(Option, OptionValue))
            ExitCode = 2
    #
    try:
        del Block
    except:
        pass

    if not ShowUsage \
    and not Arguments:
        eprint("No paths stated")
        ExitCode = 2
    #
    if not ShowUsage \
    and ExitCode == 0 \
    and len(Blocks) == 0:
        eprint("No blocks stated")
        ExitCode = 2
    #
    if ShowUsage \
    or ExitCode:
        showUsage()
        sys.exit(ExitCode)

    BlocksByOffset = sorted(Blocks, key=lambda x: (x["OFFSET"], x["SIZE"]))

    if DebugLevel >= 3:
        dprint("BlocksByOffset:")
        for _i in range(len(BlocksByOffset)):
            dprint("{}:".format(_i), BlocksByOffset[_i])

    ## Process paths
    for Source in Arguments:
        print(">>>>>>>>>> PKG Source:", Source)

        ## Initialize per-file variables
        DataStream = PkgReader(Source, DebugLevel)
        FileSize = DataStream.getSize(DebugLevel)
        print("File Size:", FileSize)

        ## Calculate necessary file blocks by combining data blocks that share file data
        FileBlocks = []
        FileParts = []
        FilePartIndex = -1
        for _i in range(len(BlocksByOffset)):
            BlockOffset = BlocksByOffset[_i]["OFFSET"]
            BlockSize = BlocksByOffset[_i]["SIZE"]

            ## Add block as file block
            Index = len(FileBlocks)
            FileBlocks.append({})
            FileBlocks[Index]["NUMBER"] = BlocksByOffset[_i]["NUMBER"]
            FileBlocks[Index]["OFFSET"] = BlockOffset
            FileBlocks[Index]["SIZE"] = BlockSize
            FileBlocks[Index]["VERIFY"] = BlocksByOffset[_i]["VERIFY"]

            ## Check block offset
            if FileSize \
            and BlockOffset >= FileSize:
                FileBlocks[Index]["SKIP"] = True
                continue

            ## Handle size
            if not FileSize \
            and BlockSize <= 0:
                FileBlocks[Index]["SKIP"] = True
                continue
            #
            RelativeSize = 0
            if BlockSize <= 0:
                FileBlocks[Index]["ORGSIZE"] = BlockSize
                RelativeSize = BlockSize
                BlockSize = FileSize + RelativeSize - BlockOffset
            if BlockSize < 1:
                FileBlocks[Index]["SKIP"] = True
                if "ORGSIZE" in FileBlocks[Index]:
                    del FileBlocks[Index]["ORGSIZE"]
                continue
            FileBlocks[Index]["SIZE"] = BlockSize

            ## Check next offset
            NextOffset = BlockOffset + BlockSize
            if FileSize \
            and NextOffset > FileSize:
                FileBlocks[Index]["SKIP"] = True
                continue

            ## Extend file block data
            FileBlocks[Index]["NEXTOFFSET"] = NextOffset

            ## Block starts a new file part
            if FilePartIndex < 0 \
            or BlockOffset >= FileParts[FilePartIndex]["NEXTOFFSET"]:
                FilePartIndex = len(FileParts)
                FileParts.append({})
                FileParts[FilePartIndex]["OFFSET"] = BlockOffset
                FileParts[FilePartIndex]["NEXTOFFSET"] = NextOffset
                FileParts[FilePartIndex]["OFFSETS"] = []
            ## Block extends current file part
            elif NextOffset > FileParts[FilePartIndex]["NEXTOFFSET"]:
                FileParts[FilePartIndex]["NEXTOFFSET"] = NextOffset

            FileParts[FilePartIndex]["OFFSETS"].extend((BlockOffset, NextOffset))

        if DebugLevel >= 1:
            dprint("FileBlocks:")
            for _i in range(len(FileBlocks)):
                dprint("{}:".format(_i), FileBlocks[_i])

        ## For each file part do a unique sort of its offsets
        for _i in range(len(FileParts)):
            FileParts[_i]["OFFSETS"] = sorted(set(FileParts[_i]["OFFSETS"]))

        if DebugLevel >= 1:
            dprint("FileParts:")
            for _i in range(len(FileParts)):
                dprint("{}:".format(_i), FileParts[_i])

        ## Read each file part in chunks derived from the offsets
        ## and calculate the CMAC and SHA hashes for each file block
        ## For definition see http://www.psdevwiki.com/ps3/PKG_files#0x40_digest
        BlockCount = len(FileBlocks)
        for _i in range(len(FileParts)):
            Hashes = {}
            for _j in range(len(FileParts[_i]["OFFSETS"])-1):
                ## Determine offset values
                BlockOffset = FileParts[_i]["OFFSETS"][_j]
                NextOffset = FileParts[_i]["OFFSETS"][_j+1]
                BlockSize = NextOffset - BlockOffset

                ## Add hashes entry for new offset
                Hashes[BlockOffset] = {}
                Hashes[BlockOffset]["CMAC"] = cmac.CMAC(algorithms.AES(CONST_PKG3_CONTENT_KEYS[0]["KEY"]), backend=default_backend())
                Hashes[BlockOffset]["SHA-1"] = hashlib.sha1()
                Hashes[BlockOffset]["SHA-256"] = hashlib.sha256()
                Hashes[BlockOffset]["MD5"] = hashlib.md5()

                ## Get data from file
                if DebugLevel >= 2:
                    dprint("Retrieve offset {:#010x} size {}".format(BlockOffset, BlockSize))
                DataBytes = None
                while BlockSize > 0:
                    if BlockSize > CONST_READ_SIZE:
                        Size = CONST_READ_SIZE
                    else:
                        Size = BlockSize
                    if DebugLevel >= 3:
                        dprint("...offset {:#010x} size {}".format(BlockOffset, Size))
                    DataBytes = DataStream.read(BlockOffset, Size, DebugLevel)
                    BlockSize -= Size
                    BlockOffset += Size

                    ## Update hashes with data
                    for _k in Hashes:
                        Hashes[_k]["CMAC"].update(DataBytes)
                        Hashes[_k]["SHA-1"].update(DataBytes)
                        Hashes[_k]["SHA-256"].update(DataBytes)
                        Hashes[_k]["MD5"].update(DataBytes)
                del DataBytes

                ## Check if any file block got completed
                for _k in range(BlockCount):
                    if "SKIP" in FileBlocks[_k] \
                    and FileBlocks[_k]["SKIP"]:
                        continue

                    if FileBlocks[_k]["NEXTOFFSET"] == NextOffset:
                        if DebugLevel >= 2:
                            dprint("Block #{} completed".format(FileBlocks[_k]["NUMBER"]))
                        BlockOffset = FileBlocks[_k]["OFFSET"]
                        FileBlocks[_k]["CMAC"] = Hashes[BlockOffset]["CMAC"].copy().finalize()
                        FileBlocks[_k]["SHA-1"] = Hashes[BlockOffset]["SHA-1"].copy().digest()
                        FileBlocks[_k]["SHA-256"] = Hashes[BlockOffset]["SHA-256"].copy().digest()
                        FileBlocks[_k]["MD5"] = Hashes[BlockOffset]["MD5"].copy().digest()

        FileBlocks = sorted(FileBlocks, key=lambda x: (x["NUMBER"]))

        for _i in range(BlockCount):
            print("Block #{} offset {:#010x} size {}{}{}".format(_i+1, FileBlocks[_i]["OFFSET"], FileBlocks[_i]["SIZE"], " ({})".format(FileBlocks[_i]["ORGSIZE"]) if "ORGSIZE" in FileBlocks[_i] else "", " (verify {})".format(FileBlocks[_i]["VERIFY"]) if FileBlocks[_i]["VERIFY"] != "DIGEST" else ""))

            if "SKIP" in FileBlocks[_i] \
            and FileBlocks[_i]["SKIP"]:
                if FileSize:
                    print("  WARNING: Skipped as it does not fit file size")
                else:
                    print("  WARNING: Skipped as its size could not be calculated")
                continue

            print("  Digest CMAC:", convertBytesToHexString(FileBlocks[_i]["CMAC"]))
            print("  Digest SHA-1 (last 8 bytes):", convertBytesToHexString(FileBlocks[_i]["SHA-1"][-8:]))
            print("  SHA-1:", convertBytesToHexString(FileBlocks[_i]["SHA-1"]))
            print("  SHA-256:".format(_i), convertBytesToHexString(FileBlocks[_i]["SHA-256"]))
            print("  MD5:".format(_i), convertBytesToHexString(FileBlocks[_i]["MD5"]))

        ## Close data stream
        DataStream.close(DebugLevel)
        del DataStream
