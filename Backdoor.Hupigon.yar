rule Backdoor_Hupigon {
   meta:
      description = "Backdoor.Hupigon"
      author = "LightDefender"
      date = "2021-06-17"
      hash1 = "730e1337cf9ecf842a965ea458ee241c2a1e5b0ef1daccde87cd628eb4b37057"
   strings:
      $s1 = "--- Log Started:"
      $s2 = "OnStartDockd5C"
      $s3 = "getServbyport"
      $s4 = "H_Client.exe"
      $s5 = "dumpInput"
      $s6 = "AutLoginTCPClientConnected"
      $s7 = "TunavclWaveOutDevice"
   condition:
      uint16(0) == 0x5a4d and (3 of them)
}
