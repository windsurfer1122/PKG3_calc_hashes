@set FILE="http://zeus.dl.playstation.net/cdn/JP3608/PCSG01200_00/JP3608-PCSG01200_00-0000000000000001_bg_1_1f292cbeb41b685b395a8fe43a24c10338162fbc.pkg"
@rem set FILE="X:\path\to\JP3608-PCSG01200_00-0000000000000001_bg_1_1f292cbeb41b685b395a8fe43a24c10338162fbc.pkg"

PKG3_calc_hashes.py -b=0,0x80,digest,ecdsa-sha1-2,0x90 -b=0,0x100,rsa-sha1-0 -b=0x280,+0x1d0,digest,rsa-sha1-0,0x490 -b=0xbf0,+0x530,sha256,0x330 -b=0,0x4b0480,digest,rsa-sha1-0,0x4b04c0 -b=0,-32,sha1 -- %FILE%
