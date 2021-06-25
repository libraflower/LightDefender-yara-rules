rule Trojan_Distool {
   meta:
      description = "Trojan.DisTool"
      date = "2021-06-26"
      author = "LightDefender"
   strings:
      $s1 = "Software\\Policies\\Microsoft\\Windows\\System\\DisableCMD" nocase
      $s2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableTaskMgr" nocase
      $s3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoRecentDocsMenu" nocase
      $s4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoLogOff"
   condition:
      uint16(0) == 0x5a4d and 2 of them
}
