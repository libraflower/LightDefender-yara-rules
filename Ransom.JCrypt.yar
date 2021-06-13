rule ransom_JCrypt {
   meta:
      description = "Ransom.JCrypt"
      author = "LightDefender"
      reference = "https://tria.ge/210205-6nvf8dqgpe"
      date = "2021-06-13"
      hash1 = "3ccc016464e41de7be959c3b00bda1296eee1c50a2897e05c1abbc9034b23027"
   strings:
      $x1 = "C:\\Users\\danie\\source\\repos\\EncrypterPOC-main\\WindowsFormsApp1\\obj\\Debug\\WindowsFormsApp1.pdb" fullword ascii
      $s2 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADSG" fullword ascii
      $s3 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii
      $s4 = "WindowsFormsApp1.exe" fullword wide
      $s5 = "friendly.cyber.criminal@gmail.com" fullword wide
      $s6 = "Afterwards, please email your transaction ID to: danielthai101514@gmail.com" fullword wide
      $s7 = "danielthai101514@gmail.com" fullword wide
      $s8 = "ENCRYPT_PASSWORD" fullword asci
      $s10 = "encryptFolderContents" fullword ascii
      $s11 = "formatFormPostEncryption" fullword ascii
      $s12 = "ENCRYPTION_LOG" fullword ascii
      $s13 = "Encryption Log:" fullword wide
      $s14 = "Password1" fullword wide
      $s15 = "\\___RECOVER__FILES__.locked.txt" fullword wide
      $s17 = ".NETFramework,Version=v4.7.2" fullword ascii
      $s18 = ".NET Framework 4.7.2" fullword ascii
      $s19 = "encryptedFileCount" fullword ascii
      $s20 = "ENCRYPT_DOCUMENTS" fullword ascii
      $s21 = "ENCRYPT_PICTURES" fullword ascii
      $s22 = "get_gesloten_slot" fullword ascii
      $s23 = "FileEncrypt" fullword ascii
      $s24 = "ENCRYPT_DESKTOP" fullword ascii
      $s25 = "ENCRYPTED_FILE_EXTENSION" fullword ascii
      $s26 = "All of your files have been encrypted." fullword wide
      $s27 = "No files to encrypt." fullword wide
      $s28 = ") have been encrypted!" fullword wide
      $s29 = "Encrypting: " fullword wide
      $s30 = "Your files (count: n) have been encrypted!" fullword wide
      $s31 = "vQGu+ !" fullword ascii
      $s32 = "RansomwarePOC.Form1.resources" fullword ascii
      $s33 = "RansomwarePOC.Properties" fullword ascii
      $s34 = "txtBitcoinAddress" fullword wide
      $s35 = "txtEmailAddress" fullword wide
      $s36 = "BITCOIN_ADDRESS" fullword ascii
      $s37 = "WindowsFormsApp1.Properties.Resources.resources" fullword ascii
      $s38 = "WindowsFormsApp1.Properties" fullword ascii
      $s40 = "WindowsFormsApp1.Properties.Resources" fullword wide
      $s41 = "To unlock them, please send 1 bitcoin(s) to BTC address: 1BtUL5dhVXHwKLqSdhjyjK9Pe64Vc6CEH1" fullword wide
      $s42 = "Please send 1 Bitcoin(s) to the following BTC address:" fullword wide
      $s43 = "CryptographicException error: " fullword wide
      $s44 = "Error by closing CryptoStream: " fullword wide
      $s45 = "Please send n Bitcoin(s) to the following BTC address:" fullword wide
      $s46 = "Next, E-mail your transaction ID to the following address:" fullword wide
      $s47 = "FileDecrypt" fullword ascii
      $s48 = "dropRansomLetter" fullword ascii
      $s49 = "16.0.0.0" fullword ascii
      $s50 = "njOwNN7" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      (1 of ($x*) or 5 of them)
}
