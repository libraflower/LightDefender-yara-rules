rule Adware_VZip {
   meta:
      description = "Adware.VZip"
      author = "LightDefender"
      date = "2021-08-02"
      hash1 = "77a85783d8c12b3112801d2cf804cc43686679c2b71fae4d677a0fa0dd956376"
   strings:
      $s1 = "SvcHostDll.dll" fullword ascii
      $s2 = "SoftHost.exe" fullword wide
      $s3 = "FSoftService.dll" fullword wide
      $s4 = "\\svchost.exe -k " fullword wide
      $s5 = "SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Svchost" fullword wide
      $s6 = "fConfig.ini" fullword wide
      $s7 = "http://sid.zhanfukeji.cn/pdf/feisu/bfcc2fc447ce7eab680c5ac5e4b3f797.ecf" fullword ascii
      $s8 = " HTTP/%d.%d %3d" fullword ascii
      $s9 = "vmissiain.ini" fullword wide
      $s10 = " StartService fail" fullword wide
   condition:
      uint16(0) == 0x5a4d and 4 of them
}
