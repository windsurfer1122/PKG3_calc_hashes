# PKG3_calc_hashes.py - To Do List

## To Do
- [ ] Verify function
  * [ ] Implement RSA for other hashes than SHA-1 (RSA-SHA256, RSA-MD5)


## Wishlist
./.


## Done
- [x] Calculate complete [PKG3 0x40 digest](http://www.psdevwiki.com/ps3/PKG_files#0x40_digest)
  * How to compute the NpDrm Signature? It's an ECDSA signature with the NPDRM pub key.
- [x] Analysis
  * [x] Find out for which data the &quot;full header&quot; RSA signature from the [extended header](https://www.psdevwiki.com/ps3/PKG_files#PKG_.ext_Header) is for?<br>
        e.g. -b=&lt;unknown start&gt;,&lt;unknwon +size/end&gt;,rsa-&lt;unknwon key&gt;,0x930 in [JP3608-PCSG01200_00-0000000000000001](http://zeus.dl.playstation.net/cdn/JP3608/PCSG01200_00/JP3608-PCSG01200_00-0000000000000001_bg_1_1f292cbeb41b685b395a8fe43a24c10338162fbc.pkg)
  * [x] Are there multiple hashes and or signatures for the same data block (not the 0x40 digest), like SHA-256 at a different offset than the digest or a RSA signature?
    * Known cases:
      * YES, meta data has digest and RSA-SHA1 sig directly following, where the RSA-SHA1 is only for the meta data itself, so excluding the  the digest
      * YES, after the body there's a digest and RSA-SHA1 sig directly following, they are for all data up to the end of the body, where the RSA-SHA1 is build without the digest.<br>
        If necessary packages are padded after these to a min. size of 100 KiB (-32)
- [x] Verify function
  * [x] Read the following bytes with digest (0x40) or SHA-1 (0x20) and compare with result
  * [x] Verify RSA SHA-1 signatures (type 2 packages)
  * [x] Allow multiple definitions of the same block or just multiple verify parameters per block
    * [x] -b 0x0,0x80,digest = digest directly following the block
    * [-] -b 0x0,0x80,sha1,digest = SHA-1 checksum (padded) directly following the block and digest directly following after that
    * [+] -b 0x0,0x80,sha1,digest,0x200 = SHA-1 checksum directly following the block and digest at a later offset
    * [+] -b 0x0,0x80,sha1 -b 0x0,0x80,digest,0x200 = same as above but in separate definitions
    * [-] -b 0x0,0x100,rsa,unknown,-1,0x200 = RSA signature for unknown checksum and unknown key located at a later offset
  [x] help shows list of possible checksums (md5, sha1, sha256) plus available AES and RSA public keys
    * [x] needs description per key
  [x] start offsets should be allowed
- [x] Calculate [PKG HMAC](http://www.psdevwiki.com/ps3/PKG_files#PKG_HMAC_algorithm)<br>
    It turned out that it is actually an RSA signature of the SHA-1 checksum for that data<br>
    The PKG HMAC from the wiki could be a special case for PSV to allow in-development packages (just guessing)
    http://zeus.dl.playstation.net/cdn/JP3608/PCSG01200_00/JP3608-PCSG01200_00-0000000000000001_bg_1_1f292cbeb41b685b395a8fe43a24c10338162fbc.pkg
- [x] More flexible block definition
  * -b &lt;start&gt;,&lt;end&gt;
    * [x] &lt;start&gt; provides flexible start offset (=first byte of data)
      * [x] positive/zero offset (&gt;=0) is absolute start offset
      * [x] negative offset (&lt;0) is offset from end of file
    * [x] &lt;end&gt; is flexible...
      * [x] +&lt;size&gt; = explicit plus sign is size of the data block
      * [x] &lt;offset&gt;
        * [x] unsigned positive offset (&gt;0) is absolute end offset (=byte after data)
        * [x] negative and zero offset (&lt;=0) is offset from end of file
- [x] Adjust input reader for minus values for file access and http requests (see PSN_get_pkg_info.py)
- [x] Switch from module cryptoghraphy to pycryptodomex (same cryptography module for all scripts)
  * [x] Revert back to cryptoghraphy when pycryptodomex &lt;3.7.2 due to a [CMAC issue](https://github.com/Legrandin/pycryptodome/issues/238)
- [x] Allow to hash values from the command line, e.g. title id for PSV update URL
  * [x] Option: --values
