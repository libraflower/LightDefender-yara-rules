rule ransom_JCrypt {
   meta:
      description = "Ransom.JCrypt"
      author = "LightDefender"
      reference = "https://tria.ge/210205-6nvf8dqgpe"
      date = "2021-06-13"
      hash1 = "3ccc016464e41de7be959c3b00bda1296eee1c50a2897e05c1abbc9034b23027"
   strings:
      $x1 = "C:\\Users\\danie\\source\\repos\\EncrypterPOC-main\\WindowsFormsApp1\\obj\\Debug\\WindowsFormsApp1.pdb" fullword ascii
      $x2 = "05c139ec-1f59-4bdf-8dec-1d7100c6e4cc" nocase ascii wide
      $x3 = "C:\\Users\\cudden\\Downloads\\EncrypterPOC-main\\EncrypterPOC-main\\WindowsFormsApp1\\obj\\Debug\\WindowsFormsApp1.pdb" fullword ascii
      $s1 = "WindowsFormsApp1.exe" fullword wide
      $s2 = "friendly.cyber.criminal@gmail.com" fullword wide
      $s3 = "Afterwards, please email your transaction ID to: danielthai101514@gmail.com" fullword wide
      $s4 = "danielthai101514@gmail.com" fullword wide
      $s5 = "ENCRYPT_PASSWORD" fullword ascii
      $s6 = "encryptFolderContents" fullword ascii
      $s7 = "formatFormPostEncryption" fullword ascii
      $s8 = "ENCRYPTION_LOG" fullword ascii
      $s9 = "Encryption Log:" fullword wide
      $s10 = "Password1" fullword wide
      $s11 = "\\___RECOVER__FILES__.locked.txt" fullword wide
      $s12 = "encryptedFileCount" fullword ascii
      $s13 = "ENCRYPT_DOCUMENTS" fullword ascii
      $s14 = "ENCRYPT_PICTURES" fullword ascii
      $s15 = "get_gesloten_slot" fullword ascii
      $s16 = "FileEncrypt" fullword ascii
      $s17 = "ENCRYPT_DESKTOP" fullword ascii
      $s18 = "ENCRYPTED_FILE_EXTENSION" fullword ascii
      $s19 = "All of your files have been encrypted." fullword wide
      $s20 = "No files to encrypt." fullword wide
      $s21 = ") have been encrypted!" fullword wide
      $s22 = "Encrypting: " fullword wide
      $s23 = "Your files (count: n) have been encrypted!" fullword wide
      $s24 = "RansomwarePOC.Form1.resources" fullword ascii
      $s25 = "RansomwarePOC.Properties" fullword ascii
      $s26 = "txtBitcoinAddress" fullword wide
      $s27 = "txtEmailAddress" fullword wide
      $s28 = "BITCOIN_ADDRESS" fullword ascii
      $s29 = "To unlock them, please send 1 bitcoin(s) to BTC address: 1BtUL5dhVXHwKLqSdhjyjK9Pe64Vc6CEH1" fullword wide
      $s30 = "Please send 1 Bitcoin(s) to the following BTC address:" fullword wide
      $s31 = "CryptographicException error: " fullword wide
      $s32 = "Error by closing CryptoStream: " fullword wide
      $s33 = "Please send n Bitcoin(s) to the following BTC address:" fullword wide
      $s34 = "Next, E-mail your transaction ID to the following address:" fullword wide
      $s35 = "FileDecrypt" fullword ascii
      $s36 = "dropRansomLetter" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      (1 of ($x*) or 5 of them)
}

rule ransom_JCrypt2 {
   meta:
      description = "Ransom.JCrypt"
      author = "LightDefender"
      date = "2021-06-13"
   strings:
      $s1 = "\\___RECOVER__FILES__.jcrypt.txt" fullword wide
      $s2 = "Your files (count: n) have been encrypted!" fullword wide
      $s3 = "\\___RECOVER__FILES__.locked.txt" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      1 of them
}
