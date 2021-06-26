rule Backdoor_VenomRAT {
   meta:
      description = "Backdoor.VenomRAT"
      author = "LightDefender"
      date = "2021-06-26"
      hash1 = "6c5664a7666e0e19f9732f2bf8e2aeefcddbfd0db6611b7ac135d999c7ef05b1"
      hash2 = "b183924fc9341c8a403e89a64ae0ac06d551db17a27fa9deafa9cc35a0d7040d"
   strings:
      $s1 = "Venombin.exe" fullword ascii
      $s2 = "user2.exe" fullword wide
      $s3 = "C:\\My Pictures.exe" fullword wide
      $s4 = "taskkill /IM cmstp.exe /F" fullword wide
      $s5 = "\\Execution.vbs" fullword wide
      $s6 = "Injecting Default Template...." fullword wide
      $s7 = "Venom\\DarkEye\\DarkEye_Passwords.zip" fullword wide
      $s8 = "Venomx64.dll" fullword wide
      $s9 = "Venomx86.dll" fullword wide
      $s10 = "Venom\\DarkEye_Passwords.zip" fullword wide
      $s11 = "D:\\CreateVenomUser\\obj\\Release\\Create.pdb" fullword ascii
      $s12 = "C:\\windows\\system32\\fodhelper.exe" fullword wide
      $s13 = "c:\\windows\\system32\\cmstp.exe" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and 2 of them
}
