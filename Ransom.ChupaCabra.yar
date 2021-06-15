rule ransom_chupacabra {
   meta:
      description = "Ransom.ChupaCabra"
      author = "LightDefender"
      reference = "https://twitter.com/Kangxiaopao/status/1402909897902022661"
      date = "2021-06-15"
      hash1 = "213d6a4c5a5c0045550fa2b822434c51dfd1b6f573c1d1bf22d9eda4f7ab2259"
      hash2 = "ce900eefb44f7e49b9c17f35caeed82d0766b71c715b89a60346c0ae19d5df78"
   strings:
      $s1 = "PasswordEncrypt" fullword ascii
      $s2 = "IMPORTANT INFORMATION!!!!" fullword wide
      $s3 = "\\HowToDecrypt.txt" fullword wide
      $s4 = "password_aes" fullword ascii
      $s5 = "\\AX754VD.tmp" fullword wide
      $s6 = "http://anubiscloud.xyz/" fullword wide
      $s7 = "EncryptFiles" fullword ascii
      $s8 = "RidjinEncrypt" fullword ascii
      $s9 = "stringa" fullword ascii
      $s10 = "ransomware" fullword ascii
      $s11 = "loki_decrypt" fullword ascii
      $s12 = "To Decrypt: " fullword wide
      $s13 = "fuWinIni" fullword ascii
      $s14 = "AESDecript" fullword ascii
      $s15 = "uAction" fullword ascii
      $s16 = "RansomwareCrypt" fullword ascii
      $s17 = "v.2.0 Reload" fullword wide
      $s18 = "4326443888886662222" wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 700KB and ( 5 of them )
      ) or ( all of them )
}

