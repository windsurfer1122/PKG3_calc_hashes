# PKG3_calc_hashes.py (c) 2018-2020 by "windsurfer1122"
Calculate hashes and verify hashes plus RSA signatures for data blocks in PS3/PSX/PSP/PSV/PSM packages.

## Goals:
* Build CMAC hashes for data, just like it is in the 0x40 digest of PKG3 packages (PS3/PSX/PSP/PSV/PSM)<br>
  For definition see http://www.psdevwiki.com/ps3/PKG_files#0x40_digest
* Additionally build other hashes used in package files, e.g. MD5, SHA-1 and SHA-256
* Build hashes for multiple data offsets and sizes in a single run, even when interleaved
* Allow to also hash values (strings) directly and not just data from a file (e.g. hash for PSV update URLs)
* Verify RSA signatures
* Verify ECDSA signatures
* Support http download streaming to avoid harddisk usage
* Support multi-part packages (PS3: XML, PS4: JSON)
* Easy to maintain and no compiler necessary (=interpreter language)
* Cross platform support
  * Decision: Python 3
    * Compatible with Python 2 (target version 2.7)
      * Identical output
      * Forward-compatible solutions preferred

## Execution
For available options execute: PKG3_calc_hashes.py -h<br>
Use at your own risk!<br>
If you state URLs then only the necessary bytes are downloaded once, but not stored on disk.

<u>Block Definitions:</u>
* A block is always specified by a start offset plus an end offset or a size.
* A size has to be specified with a leading plus sign.
* Offsets can be negative to define it relative to the file end.
* Special case is zero for the end offset which is also relative to the file end.

<u>Block Examples:</u>
* To calculate the digest values for the main header use: -b=0,+0x80 (offset plus size) or -b 0,128 (offsets)<br>
  To add verification use: -b=0,+0x80,digest
* To calculate the SHA-1 for all data, which is stored in the last 32 bytes of each package, use: -b=0,-32
* To calculate the SHA-256 for the whole package use: -b=0,0
* Real life definitions for [JP3608-PCSG01200_00-0000000000000001](http://zeus.dl.playstation.net/cdn/JP3608/PCSG01200_00/JP3608-PCSG01200_00-0000000000000001_bg_1_1f292cbeb41b685b395a8fe43a24c10338162fbc.pkg) (5 MiB):
  * Main header digest: -b=0,0x80,digest
  * Main+Ext header RSA: -b=0,0x100,rsa-0
  * Meta data digest+RSA: -b=0x280,+0x1d0,digest,rsa-0,0x490
  * Unencrypted PARAM.SFO: -b=0xbf0,+0x530,sha256,0x330
  * Head+Body digest+RSA: -b=0,0x4b0480,digest,rsa-0,0x4b04c0
  * Tail SHA1: -b=0,-32,sha1
  * Hashes for complete file: -b=0,0

## Contributions welcome
* Especially information about how to interpret data is needed, e.g. link between data and RSA signatures
* See TODO.md what is still left to do

## Requirements
* Python Modules
  * [pycryptodomex](https://www.pycryptodome.org/) >= 3.7.2 (note the X at the end of the module name)<br>
    https://www.pycryptodome.org/en/latest/src/installation.html
  * [cryptography](https://cryptography.io/) (optional if pycryptodomex 3.7.2+ is not available)
  * [requests](http://python-requests.org/)
  * [aenum](https://bitbucket.org/stoneleaf/aenum)
  * [packaging](https://github.com/pypa/packaging)
  * [ecdsa](https://github.com/warner/python-ecdsa)

### Installing on Debian
1. Python 3, which is the recommended version, and most modules can be installed via apt.<br>
Install Python 3 and some modules via the following apt packages: `python3 python3-pip python3-requests`.<br>

1. Python 2 is the default on Debian, but comes with an outdated pip version until Debian 8.<br>
__Starting with Debian 9 "Stretch"__ install Python 2 modules via the following apt packages: `python-pip python-future python-requests`.<br>
For __Debian up to 8 "Jessie"__ use the pip version from the original [PyPi](https://pypi.org/project/pip/) source:<br>
   ```
   apt-get purge python-pip python-dev python-future
   apt-get autoremove
   wget https://bootstrap.pypa.io/get-pip.py
   python2 get-pip.py
   pip2 install --upgrade future
   ```

1. Install further necessary Python modules via pip.
   * Install pycryptodomex module:<br>
     https://www.pycryptodome.org/en/latest/src/installation.html
     * Python 3: `pip3 install --upgrade pycryptodomex`
     * Python 2: `pip2 install --upgrade pycryptodomex`
   * Install cryptography module:
     * Python 3: `pip3 install --upgrade cryptography`
     * Python 2: `pip2 install --upgrade cryptography`
   * Install aenum module:
     * Python 3: `pip3 install --upgrade aenum`
     * Python 2: `pip2 install --upgrade aenum`
   * Install packaging module:
     * Python 3: `pip3 install --upgrade packaging`
     * Python 2: `pip2 install --upgrade packaging`
   * Install ecdsa module:
     * Python 3: `pip3 install --upgrade ecdsa`
     * Python 2: `pip2 install --upgrade ecdsa`

### Installing on Windows
1. Install Python<br>
   Checked with Python 3.7 x64 on Windows 10 x64 Version 1803.
   * Get it from the [Python homepage](https://www.python.org/)
   * Install launcher for all users
   * Add Python to PATH<br>
     Adds %ProgramFiles%\Python37 + \Scripts to PATH
   * __Use Customize Installation (!!! necessary for advanced options !!!)__
   * Advanced Options
     * Install for all users

1. Install necessary Python modules via pip.
   * Start an __elevated(!!!)__ Command Prompt (Run As Admin via Right Click)
   * Update PIP itself first: `python -m pip install --upgrade pip`
   * Install pycryptodomex module: `pip install --upgrade pycryptodomex`<br>
     https://www.pycryptodome.org/en/latest/src/installation.html
   * Install cryptography module: `pip install --upgrade cryptography`
   * Install requests module: `pip install --upgrade requests`
   * Install aenum module: `pip install --upgrade aenum`
   * Install packaging module: `pip install --upgrade packaging`
   * Install ecdsa module: `pip install --upgrade ecdsa`
   * Exit Command Prompt: `exit`

Executing python scripts can be done via Windows Explorer or a Command Prompt. Normally no elevation is necessary for script execution, except when the python script wants to change something in the system internals.

## Using a HTTP Proxy with Python
* Linux: `export HTTP_PROXY="http://192.168.0.1:3128"; export HTTPS_PROXY="http://192.168.0.1:1080";`

## Original Source
git master repository at https://github.com/windsurfer1122

## License
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

## Additional Credits for Ideas and Several Details
* https://playstationdev.wiki/ (previously https://vitadevwiki.com/ & https://www.pspdevwiki.com/)
* http://www.psdevwiki.com/
* [CelesteBlue](https://github.com/CelesteBlue-dev)
