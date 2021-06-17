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
 rule CoinMiner_WannaMine_Strings {
   meta:
      description = "CoinMiner.WannaMine"
      author = "LightDefender"
      date = "2021-06-17"
      hash1 = "148193ec3e862b3188f92a3d72eca85d82fc2cd9edbc162b4947e0911fea780a"
      hash2 = "d9c028aef6c9636d44e1c557db4338301fc57a1441ccb4fd9c73251c5f84d036"
   strings:
      $s1 = "zibe.dll" fullword ascii
      $s2 = "tibe.dll" fullword ascii
      $s3 = "trfo.dll" fullword ascii
      $s4 = "trch.dll" fullword ascii
      $s5 = "eteb-2.dll" fullword ascii
      $s6 = "dmgd-4.dll" fullword ascii
      $s7 = "cnli-1.dll" fullword ascii
      $s8 = "etch-0.dll" fullword ascii
      $s9 = "etebCore-2.x86.dll" fullword ascii
      $s10 = "trfo-0.dll" fullword ascii
      $s11 = "tibe-1.dll" fullword ascii
      $s12 = "xdvl-0.dll" fullword ascii
      $s13 = "out.dll" fullword ascii
      $s14 = "esco-0.dll" fullword ascii
      $s15 = "coli-0.dll" fullword ascii
      $s16 = "pcla-0.dll" fullword ascii
      $s17 = "pcreposix-0.dll" fullword ascii
      $s18 = "etebCore-2.x64.dll" fullword ascii
      $s19 = "dmgd-1.dll" fullword ascii
      $s20 = "WNTNUNSNW" fullword ascii /* base64 encoded string '53T5#V' */
      $s21 = "crli-0.dll" fullword ascii
      $s22 = "svchost.xml" fullword ascii
      $s23 = "Yi5jZzAzU" fullword ascii /* base64 encoded string 'b.cg03' */
      $s24 = "nzpFp.qxf#" fullword ascii
      $s25 = "spoolsv.xml" fullword ascii
      $s26 = "!>$>\">2>*>>>)>%>5>->+>;" fullword ascii /* hex encoded string '%' */
      $s27 = "$;:;&;6;.;>;!;1;#;3;+;;;';7;/;?" fullword ascii /* hex encoded string 'a7' */
      $s28 = "Knh -f " fullword ascii
      $s29 = "5><%6%)%-%/" fullword ascii /* hex encoded string 'V' */
      $s30 = "!256&),))5" fullword ascii /* hex encoded string '%e' */
      $s31 = "6-(- -0-\"mCZr" fullword ascii
      $s32 = "sopotov" fullword ascii
      $s33 = "zrsuqsuas" fullword ascii
      $s34 = "crmxfpc" fullword ascii
      $s35 = "gilihik" fullword ascii
      $s36 = "wgtgrgv" fullword ascii
      $s37 = "uwknkikz" fullword ascii
      $s38 = "hkooioboaonokoj" fullword ascii
      $s39 = "=^MD:\\" fullword ascii
      $s40 = "tk:\\|z" fullword ascii
      $s41 = "t:\"t18" fullword ascii
      $s42 = " lPiPe" fullword ascii
      $s43 = "_pytrch.pyd" fullword ascii
      $s44 = "|E:\\g(2" fullword ascii
      $s45 = "logE56" fullword ascii
      $s46 = "8f_4Sp:\\B3" fullword ascii
      $s47 = "7UB.CEq~h" fullword ascii
      $s48 = "VYTYVYUYW" fullword ascii
      $s49 = "UMUYUEU" fullword ascii
      $s50 = "95786b6c28bf8dba7bbfeeba9e1ec27a" ascii
      $s51 = ",\\.\\V\\" fullword ascii
      $s52 = "boE^EAEYE~" fullword ascii
      $s53 = "~!\\.\\$\\\"\\!T" fullword ascii
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x4b50 ) and filesize < 20000KB and ( 8 of them )
      ) or ( all of them )
}

