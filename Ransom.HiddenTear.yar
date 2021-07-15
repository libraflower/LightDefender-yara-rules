rule Ransom_HiddenTear_1
{
    meta:
        description = "Open-Source ransomware available on Github since 2015, with many versions in the wild."
        author = "LightDefender"
        date = "2021-06-28"
    strings:
        $s1 = "computerName" fullword ascii
        $s2 = "userDir" fullword ascii
        $s3 = "userName" fullword ascii
        $s4 = "AES_Encrypt" fullword ascii
        $s5 = "CreatePassword" fullword ascii
        $op1 = {72????0070 28??00000A 6F??00000A 28??00000A 6F??00000A 26}
        $x1 = "7ab0dd04-43e0-4d89-be59-60a30b766467" nocase ascii wide
    condition:
        uint16(0) == 0x5a4d and (4 of ($s*) or any of ($op*) or any of ($x*))
}

rule MAL_RANSOM_COVID19_Apr20_1 {
   meta:
      description = "Detects ransomware distributed in COVID-19 theme"
      author = "Florian Roth"
      reference = "https://unit42.paloaltonetworks.com/covid-19-themed-cyber-attacks-target-government-and-medical-organizations/"
      date = "2020-04-15"
      hash1 = "2779863a173ff975148cb3156ee593cb5719a0ab238ea7c9e0b0ca3b5a4a9326"
   strings:
      $s1 = "/savekey.php" wide

      $op1 = { 3f ff ff ff ff ff 0b b4 }
      $op2 = { 60 2e 2e 2e af 34 34 34 b8 34 34 34 b8 34 34 34 }
      $op3 = { 1f 07 1a 37 85 05 05 36 83 05 05 36 83 05 05 34 }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 700KB and
      2 of them
}
