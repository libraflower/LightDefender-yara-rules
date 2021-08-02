rule TrojanDownloader_DuoTe {
   meta:
      description = "TrojanDownloader.DuoTe"
      author = "LightDefender"
      date = "2021-08-02"
      hash1 = "c09d01b766a78bbd228d25a21acaef6e898618cb5831e5d31bd166625890fabb"
      hash2 = "aad538309b8708e7a39b457e2ed3a692130040b4b51c19353ccd947afa029d27"
   strings:
      $s1 = "http://t.duote.com/duote/index.php" fullword wide
      $s2 = "DuoteInstall" fullword wide
   condition:
      uint16(0) == 0x5a4d and any of them
}
