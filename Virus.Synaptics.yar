rule Virus_Synaptics {
   meta:
      description = "Virus.Synaptics"
      author = "LightDefender"
      date = "2021-06-18"
      hash1 = "1c1358545fae2f6eae1b7cf761c8c6d1df982d779c2b8d3dd96bf19027441269"
   strings:
      $s1 = "Synaptics.dll"
      $s2 = "Synaptics.exe"
      $s3 = "http://xred.site50.net/syn/Synaptics.rar"
      $s4 = "xredline2@gmail.com;xredline3@gmail.com"
      $s5 = "https://www.dropbox.com/s/zhp1b06imehwylq/Synaptics.rar?dl=1"
      $s6 = "https://docs.google.com/uc?id=0BxsMXGfPIZfSTmlVYkxhSDg5TzQ&export=download"
      $s7 = "._cache_" fullword ascii
      $s8 = "autorun.inf" fullword ascii
      $s9 = ".exe" fullword ascii
      $s10 = ".xlsx" fullword ascii
      $s11 = "0\"0*020:0B0J0R0Z0b0j0r0z0" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize > 500KB and all of them
}
