rule spy_avemariarat {
   meta:
      description = "TrojanSpy.AveMariaRAT"
      author = "LightDefender"
      date = "2021-06-13"
      hash1 = "ac14bf805d1796f1463b5f27b79496dab9a07f5bd50336628bcfbdc2dc996acf"
   strings:
      $x1 = "cmd.exe /C ping 1.2.3.4 -n 2 -w 1000 > Nul & Del /f /q " fullword ascii
      $x2 = "c:\\windows\\system32\\user32.dll" fullword ascii
      $x3 = "C:\\Users\\Vitali Kremez\\Documents\\MidgetPorn\\workspace\\MsgBox.exe" fullword wide
      $x4 = "\\System32\\cmd.exe" fullword wide
      $s5 = "dUser32.dll" fullword wide
      $s6 = "@\\cmd.exe" fullword wide
      $s7 = "find.exe" fullword ascii
      $s8 = "SMTP Password" fullword wide
      $s9 = "Ave_Maria Stealer OpenSource github Link: https://github.com/syohex/java-simple-mine-sweeper" fullword wide
      $s10 = "\\Opera Software\\Opera Stable\\Login Data" fullword wide
      $s11 = "\\rfxvmt.dll" fullword wide
      $s12 = "\\sqlmap.dll" fullword wide
      $s13 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList" fullword ascii
      $s14 = "            <assemblyIdentity  name=\"Package_1_for_KB929761\" version=\"6.0.1.1\" language=\"neutral\" processorArchitecture=\"" ascii
      $s15 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook\\9375CFF0413111d3B88A00104B2A667" wide
      $s16 = "\\Comodo\\Dragon\\User Data\\Default\\Login Data" fullword wide
      $s17 = "/n:%temp%\\ellocnak.xml" fullword wide
      $s18 = "POP3 Password" fullword wide
      $s19 = "IMAP Password" fullword wide
      $s20 = "\\Google\\Chrome\\User Data\\Default\\Login Data" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      ((1 of ($x*) and 4 of them) or 6 of them)
}
