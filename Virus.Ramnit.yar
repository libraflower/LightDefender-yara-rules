rule Virus_Ramnit_infected {
   meta:
      description = "Virus.Ramnit"
      author = "LightDefender"
      date = "2021-08-03"
   strings:
      $Name = "Srv.exe" fullword ascii
      $section_name = {2E 72 6D 6E 65 74}
   condition:
      uint16(0) == 0x5a4d and
      all of them
}

rule Ramnit_DesktopLayer {
   meta:
      description = "Detects DesktopLayer.exe"
      author = "LightDefender"
      date = "2021-08-03"
   strings:
      $FileDescription = "BitDefender Management Console" fullword wide
      $FileVersion = "106.42.73.61" fullword wide
   condition:
      uint16(0) == 0x5a4d and
      all of them
}

rule Ramnit_Opcodes {
   meta:
      description = "Detects Ramnit"
      author = "LightDefender"
      date = "2021-08-03"
   strings:
      $op1 = {558BEC83C480C745C437000000314D8CFF45A4E8}
   condition:
      uint16(0) == 0x5a4d and
      any of them
}
