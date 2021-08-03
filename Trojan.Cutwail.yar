rule Trojan_Cutwail_1 {
   meta:
      description = "Trojan.Cutwail"
      author = "LightDefender"
      date = "2021-08-03"
      hash1 = "439be843a67288b16e1df174691954c0d531b7e4c96f5af6780ae1d7a8532ebe"
   strings:
      $x1 = "C:\\Users\\WMJI\\gaszilanfofg.exe" fullword ascii
      $x2 = "\\system32\\svchost.exe" fullword ascii
      $x3 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)" fullword ascii
      $x4 = "if exist %s goto :repeat" fullword ascii
      $s5 = "zlbqgtrknxfspcmd" fullword ascii
      $s6 = "WinServer2012" fullword ascii
      $s7 = "Katzacozuf" fullword ascii
      $s8 = "WinXP64" fullword ascii
      $s9 = "WinServer2008" fullword ascii
      $s10 = "WinServer2003" fullword ascii
      $s11 = "software\\microsoft\\windows\\currentversion\\run" fullword ascii
      $s12 = "WinServer2008R2" fullword ascii
      $s13 = "WinServer2003R2" fullword ascii
      $s14 = "qkbhctjdwfglmpxzrvsn" fullword ascii
      $s15 = "gaszilanfofg" fullword ascii
      $s16 = "http://www.%s" fullword ascii
      $s17 = "MyDefaultKeyContainer" fullword ascii
      $s18 = "software\\microsoft\\windows\\currentversion\\uninstall" fullword ascii
      $s19 = "Wjceeaspmouaq" fullword ascii
      $s20 = "Jahoxakejet" fullword ascii
   condition:
      uint16(0) == 0x5a4d and
      1 of ($x*) and 5 of them
}

rule Trojan_Cutwail_2 {
   meta:
      description = "Trojan.Cutwail"
      author = "LightDefender"
      date = "2021-08-03"
      hash1 = "b75def147a5d9cfc7306f899d60e3775955feee9870238d0bafdff1ecd523678"
   strings:
      $s1 = "PhoneBook.EXE" fullword wide
      $s2 = "C:\\\\\\\\\\\\\\wIndIWS\\\\\\\\explorEr.exe.\\\\\\\\\\" fullword ascii
      $s3 = "mailto://zjf-2004@163.com" fullword ascii
      $s4 = "zjf-2004@163.com" fullword wide
      $s5 = "ODBC Connection Faile!" fullword ascii
      $s6 = "Unknown Error (%d) occurred." fullword ascii
      $s7 = "ODBC;DRIVER=Microsoft Access Driver (*.mdb);DSN='';DBQ=telbook.mdb" fullword ascii
      $s8 = "select * from personlist" fullword ascii
      $s9 = "telphone" fullword ascii
      $s10 = "[address]" fullword ascii
      $s11 = "[company]" fullword ascii
      $s12 = "[mobile]" fullword ascii
   condition:
      uint16(0) == 0x5a4d and
      6 of them
}
