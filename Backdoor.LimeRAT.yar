rule Backdoor_LimeRAT {
   meta:
      description = "LimeRAT"
      author = "LightDefender"
      date = "2021-07-05"
      hash1 = "68fa85b4462c2a3d0c428b59c2915716d5af5c6416bd6aa3efdff627ecad0f07"
      hash2 = "cd2de593f63473739be4a97af6f1a7ccf92fe704b70a3ea4568267e059251f41"
   strings:
      $s1 = "select CommandLine from Win32_Process where Name='{0}'" fullword wide
      $s2 = "\\vboxhook.dll" fullword wide
      $s3 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii
      $s4 = "Win32_Processor.deviceid=\"CPU0\"" fullword wide
      $s5 = "Select * from Win32_ComputerSystem" fullword wide
      $s6 = "Y21kLmV4ZSAvYyBwaW5nIDAgLW4gMiAmIGRlbCA=" fullword wide /* base64 encoded string 'cmd.exe /c ping 0 -n 2 & del ' */
      $s7 = "Flood! " fullword wide
      $s8 = "Error! " fullword wide
      $s9 = "microsoft corporation" fullword wide
      $s10 = "VirtualBox" fullword wide
      $s11 = "_Lambda$__R12-1" fullword ascii
      $s12 = "ES_CONTINUOUS" fullword ascii
      $s13 = "SELECT * FROM AntivirusProduct" fullword wide
      $s14 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and ( 6 of them )
      ) or ( all of them )
}

rule Backdoor_LimeRAT_2 {
   meta:
      description = "LimeRAT"
      author = "LightDefender"
      date = "2021-07-17"
   strings:
      $s1 = "_Lambda$__R13-2" fullword ascii
      $s2 = "Win32_Processor.deviceid=\"CPU0\"" fullword wide
      $s3 = "schtasks /create /f /sc ONLOGON /RL HIGHEST /tn LimeRAT-Admin /tr \"'" fullword wide
   condition:
      uint16(0) == 0x5a4d and 2 of them
}
