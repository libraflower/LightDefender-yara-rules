rule Backdoor_amcshd {
   meta:
      description = "Backdoor.amcshd"
      author = "LightDefender"
      reference = "https://twitter.com/IntezerLabs/status/1409844721992749059?s=20"
      date = "2021-06-29"
      hash1 = "3afe2ec273608be0b34b8b357778cc2924c344dd1b00a84cf90925eeb2469964"
      hash2 = "3de97c2b211285022a34a62b536cef586d987939d40d846930c201d010517a10"
      hash3 = "79e93f6e5876f31ddc4a6985b290ede6a2767d9a94bdf2057d9c464999163746"
      hash4 = "7fa37dd67dcd04fc52787c5707cf3ee58e226b98c779feb45b78aa8a249754c7"
      hash5 = "b00157dbb371e8abe19a728104404af61acc3c5d4a6f67c60e694fe0788cb491"
   strings:
      $s1 = "exec bash --login" fullword ascii
      $s2 = "gethostbyname@@GLIBC_2.2.5" fullword ascii
      $s3 = "debuglog" fullword ascii
      $s4 = "execl@@GLIBC_2.2.5" fullword ascii
      $s5 = "magickey" fullword ascii
      $s6 = "read %d from pty fd" fullword ascii
      $s7 = "getpwd" fullword ascii
      $s8 = "getotp" fullword ascii
      $s9 = "About to connect to %s:%s" fullword ascii
      $s10 = "Got new win size:%d,%d" fullword ascii
      $s11 = "daemonme" fullword ascii
      $s12 = "chtitle" fullword ascii
      $s13 = "base32_decode" fullword ascii
      $s14 = "nc.cai1688.com" fullword ascii
      $x1 = "T57ROOTATOPENWILLDOTME" fullword ascii
      $x2 = "amcsh_connect" fullword ascii
      $x3 = "daemonme" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 70KB and ( 4 of them )
      ) or ( all of them ) or (all of ($x*))
}
