# PKG3_calc_hashes.py (c) 2018 by "windsurfer1122"
Calculate hashes for data blocks inside PS3/PSX/PSP/PSV/PSM packages.

<u>Goals:</u>
* Build CMAC hashes of data, just like it is used in the 0x40 digest of PKG3 packages (PS3/PSX/PSP/PSV/PSM)<br>
  For definition see http://www.psdevwiki.com/ps3/PKG_files#0x40_digest
* Additionally build other hashes used in package files, e.g. MD5, SHA-1 and SHA-256
* Build hashes for multiple data offsets and sizes in a single run, even when interleaved
* Support http download streaming to avoid harddisk usage
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


<u>Block Examples:</u>
* To calculate the digest for the main header, use -b 0,128

You can also use zero (0) and negative sizes to specify the block end relative to the file end.
* To calculate the SHA-1 for all data, which is stored in the last 32 bytes of each package, use -b 0,-32,sha-1
* To calculate the SHA-256 for the whole file, use -b 0,0,none

## Requirements
* Python Modules
  * [cryptography](https://cryptography.io/)
  * requests

### Installing on Debian
1. Most Python modules can be installed via apt.<br>
Install Python 3 modules via the following apt packages: python3-requests python3-cryptography.<br>
As Python 2 is the default on Debian and this version should be used, then install apt packages: python-future python-requests python-cryptography.

1. Install pycryptodomex module via pip<br>
   Python 3: `pip3 install pycryptodomex`<br>
   Python 2: `pip2 install pycryptodomex`

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

1. Install necessary Python modules
   * Start an elevated(!!!) Command Prompt (Run As Admin via Right Click)
   * Update PIP first: `python -m pip install --upgrade pip`
   * Install requests module: `pip install requests`
   * Install pycryptodomex module: `pip install pycryptodomex`
   * Install cryptography module: `pip install cryptography`
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
