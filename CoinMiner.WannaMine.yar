rule CoinMiner_WannaMine_Opcodes {
   meta:
      description = "CoinMiner.WannaMine"
      author = "LightDefender"
      date = "2021-06-17"
   strings:
      $s1 = {558BEC83EC10A05BE241008B550C8BCA}
      $s2 = {8B45008954243C03D081FAA00500000F}
      $s3 = {558BEC6AFF68786F410064A100000000}
   condition:
      uint16(0) == 0x5a4d and all of them
 }
 rule CoinMiner_WannaMine {
   meta:
      description = "CoinMiner.WannaMine"
      author = "LightDefender"
      date = "2021-06-17"
      hash1 = "148193ec3e862b3188f92a3d72eca85d82fc2cd9edbc162b4947e0911fea780a"
   strings:
      $x1 = "cmd.exe /c ping 127.0.0.1 -n 5 & cmd.exe /c del /a /f \"%s\"" fullword wide
      $s2 = "trch.dll" fullword ascii
      $s3 = "tibe.dll" fullword ascii
      $s4 = "zibe.dll" fullword ascii
      $s5 = "trfo.dll" fullword ascii
      $s6 = "Installe.exe" fullword wide
      $s7 = "\\svchost.exe" fullword ascii
      $s8 = "cnli-1.dll" fullword ascii
      $s9 = "eteb-2.dll" fullword ascii
      $s10 = "trfo-0.dll" fullword ascii
      $s11 = "tibe-2.dll" fullword ascii
      $s12 = "esco-0.dll" fullword ascii
      $s13 = "tibe-1.dll" fullword ascii
      $s14 = "Enables a common interface and object model for the %s to access management information about system update, network protocols, " ascii
      $s15 = "dmgd-1.dll" fullword ascii
      $s16 = "etch-0.dll" fullword ascii
      $s17 = "coli-0.dll" fullword ascii
      $s18 = "etebCore-2.x64.dll" fullword ascii
      $s19 = "etebCore-2.x86.dll" fullword ascii
      $s20 = "xdvl-0.dll" fullword ascii
      $s21 = "pcla-0.dll" fullword ascii
      $s22 = "dmgd-4.dll" fullword ascii
      $s23 = "out.dll" fullword ascii
      $s24 = "pcreposix-0.dll" fullword ascii
      $s25 = "WNTNUNSNW" fullword ascii /* base64 encoded string '53T5#V' */
      $s26 = "crli-0.dll" fullword ascii
      $s27 = "svchost.xml" fullword ascii
      $s28 = "/install.php?os=%s&host=%s&%s" fullword ascii
      $s29 = "Enables a common interface and object model for the %s to access management information about system update, network protocols, " ascii
      $s30 = "MACHINE\\SYSTEM\\CurrentControlSet\\Services\\%s" fullword ascii
      $s31 = "Mozilla/4.0 (compatible; MSIE 6.1; Windows NT)" fullword ascii
      $s32 = "Yi5jZzAzU" fullword ascii /* base64 encoded string 'b.cg03' */
      $s33 = " inflate 1.1.4 Copyright 1995-2002 Mark Adler " fullword ascii
      $s34 = " Type Descriptor'" fullword ascii
      $s35 = "disabled, any services that depend on it will fail to start." fullword ascii
      $s36 = "spoolsv.xml" fullword ascii
      $s37 = "nzpFp.qxf#" fullword ascii
      $s38 = "3 3'3.3;3|3" fullword ascii /* hex encoded string '333' */
      $s39 = "!>$>\">2>*>>>)>%>5>->+>;" fullword ascii /* hex encoded string '%' */
      $s40 = "!256&),))5" fullword ascii /* hex encoded string '%e' */
      $s41 = "5><%6%)%-%/" fullword ascii /* hex encoded string 'V' */
      $s42 = "$;:;&;6;.;>;!;1;#;3;+;;;';7;/;?" fullword ascii /* hex encoded string 'a7' */
      $s43 = "6-(- -0-\"mCZr" fullword ascii
      $s44 = "Knh -f " fullword ascii
      $s45 = "hkooioboaonokoj" fullword ascii
      $s46 = "%d_%d_%d_%d_%d_%d" fullword ascii
      $s47 = "devices and applications. If this service is stopped, most Kernel-based software will not function properly. If this service is " ascii
      $s48 = "uwknkikz" fullword ascii
      $s49 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\NetworkPlatform\\Location Awareness" fullword ascii
      $s50 = "sopotov" fullword ascii
      $s51 = "netsvcs" fullword ascii
      $s52 = "gilihik" fullword ascii
      $s53 = "zrsuqsuas" fullword ascii
      $s54 = "wgtgrgv" fullword ascii
      $s55 = "crmxfpc" fullword ascii
      $s56 = "-/K:tI:\\" fullword ascii
      $s57 = "|E:\\g(2" fullword ascii
      $s58 = "_pytrch.pyd" fullword ascii
      $s59 = "=^MD:\\" fullword ascii
      $s60 = "t:\"t18" fullword ascii
      $s61 = "Error_%d" fullword ascii
      $s62 = "logE56" fullword ascii
      $s63 = "7UB.CEq~h" fullword ascii
      $s64 = "8f_4Sp:\\B3" fullword ascii
      $s65 = " lPiPe" fullword ascii
      $s66 = "tk:\\|z" fullword ascii
      $s67 = "Aapi-ms-win-appmodel-runtime-l1-1-1" fullword wide
      $s68 = "VYTYVYUYW" fullword ascii
      $s69 = "UMUYUEU" fullword ascii
      $s70 = " Class Hierarchy Descriptor'" fullword ascii
      $s71 = ",\\.\\V\\" fullword ascii
      $s72 = "boE^EAEYE~" fullword ascii
      $s73 = "185.128.24.101" fullword ascii
      $s74 = " Base Class Descriptor at (" fullword ascii
      $s75 = "6c1dadd288f20749a0ef885565852836" ascii
      $s76 = "95786b6c28bf8dba7bbfeeba9e1ec27a" ascii
      $s77 = "af26e85b0a87dd33e1b8cfee66abdaf3" ascii
      $s78 = "a87fff59dd3d19ab2a4081339bffd6fe" ascii
      $s79 = "Rbemckg" fullword ascii
      $s80 = "~!\\.\\$\\\"\\!T" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 20000KB and
      4 of them
}
