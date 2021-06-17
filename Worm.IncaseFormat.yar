rule Worm_IncaseFormat {
   meta:
      description = "Worm.IncaseFormat"
      author = "LightDefender"
      date = "2021-06-18"
      hash1 = "75ee468476e300c5fddda280a2c0570b1c11a0f7c44acad2b257428cf404e5da"
   strings:
      $s1 = "C:\\windows\\tsay.exe" fullword ascii
      $s2 = "C:\\windows\\ttry.exe" fullword ascii
      $s3 = "incaseformat.log" fullword ascii
      $s4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Folder\\HideFileExt" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      2 of them
}
