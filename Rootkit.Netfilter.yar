rule TrojanDropper_Netfilter {
   meta:
      description = "TrojanDropper.Netfilter"
      author = "LightDefender"
      date = "2021-07-02"
      hash1 = "a5c873085f36f69f29bb8895eb199d42ce86b16da62c56680917149b97e6dac4"
   strings:
      $s1 = "%s\\netfilter.sys" fullword ascii
      $s2 = "SYSTEM\\CurrentControlSet\\Services\\netfilter" fullword ascii
      $s3 = "\\\\.\\netfilter" fullword ascii
      $s4 = "r\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" fullword wide
      $s5 = "sSYSTEM\\CurrentControlSet\\Services\\netfilter" fullword wide
      $s6 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36 Edg/89.0.774" ascii
      $s7 = "netfilter" fullword wide
      $s8 = "regini" fullword ascii
      $s9 = "SeLoadDriverPrivilege" fullword wide
      $s10 = "Wininet.dll" fullword ascii
      $s11 = "c.xalm" fullword ascii
      $s12 = "http://45.113.202.180:608/d3" fullword ascii
      $s13 = "http://45.113.202.180:608/d6" fullword ascii
      $s14 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36" fullword ascii
      $s15 = "%s\\loader.exe" fullword ascii
      $s16 = "TSYSTEM\\CurrentControlSet\\Services\\netfilter" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB
      5 of them
}

rule Rootkit_Netfilter {
   meta:
      description = "Rootkit.Netfilter"
      author = "LightDefender"
      date = "2021-07-02"
      hash1 = "f83c357106a7d1d055b5cb75c8414aa3219354deb16ae9ee7efe8ee4c8c670ca"
   strings:
      $pdb1 = {00 43 3A 5C 55 73 65 72 73 5C 6F 6D 65 6E 5C 44 65 73 6B 74 6F 70 5C E6 96 B0 E5 BB BA E6 96 87 E4 BB B6 E5 A4 B9 20 28 34 29 5C 78 36 34 5C 52 65 6C 65 61 73 65 5C 6E 65 74 66 69 6C 74 65 72 64 72 76 2E 70 64 62 00}
      $pdb2 = {00 47 3A 5C E6 BA 90 E7 A0 81 5C 68 65 6C 6C 6F 5C 52 65 6C 65 61 73 65 5C 6E 65 74 66 69 6C 74 65 72 64 72 76 2E 70 64 62 00}
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB
      any of them
}
