rule Virus_Synaptics {
   meta:
      description = "Virus.Synaptics (Delf)"
      author = "LightDefender"
      date = "2021-06-18"
      hash1 = "1c1358545fae2f6eae1b7cf761c8c6d1df982d779c2b8d3dd96bf19027441269"
   strings:
      $s1 = "Synaptics.dll"
      $s2 = "Synaptics.exe"
      $s3 = "http://xred.site50.net/syn/Synaptics.rar"
      $s4 = "xredline2@gmail.com;xredline3@gmail.com"
      $s5 = "Directory Watcher -> Active"
   condition:
      uint16(0) == 0x5a4d and all of them
}
