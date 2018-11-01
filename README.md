# PKG3_calc_hashes.py (c) 2018 by "windsurfer1122"
Calculate hashes for data blocks inside PS3/PSX/PSP/PSV/PSM packages.

<u>Goals:</u>
* Build CMAC and SHA-1/256 hashes of data, just like it is used in the 0x40 digest of PKG3 packages (PS3/PSX/PSP/PSV/PSM)<br>
  For definition see http://www.psdevwiki.com/ps3/PKG_files#0x40_digest
* Support of all known package types: PS3/PSX/PSP, PSV/PSM
* Easy to maintain and no compiler necessary (=interpreter language)
* Cross platform support
  * Decision: Python 3
    * Compatible with Python 2 (target version 2.7)
      * Identical output
      * Forward-compatible solutions preferred

For options execute: PKG3_calc_hashes.py -h<br>
Use at your own risk!
If you state URLs then only the necessary bytes are downloaded once, but not stored on disk.


<u>Block Examples:</u>
* To calculate the digest for the main header, use -b 0,128
You can also use zero (0) and negative sizes to specify the block end relative to the file end.
* To calculate the SHA-1 for all data, which is stored in the last 32 bytes of each package, use -b 0,-32,sha-1
* To calculate the SHA-256 for the whole file, use -b 0,0,none


<u>Requirements:</u>
* Python Modules
  * cryptography
  * requests (normally already present)

On Windows try "pip install <modulename>".<br>
On Linux install the corresponding packages, e.g. Debian python-<modulename> or python3-<modulename>.


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


git master repository at https://github.com/windsurfer1122
