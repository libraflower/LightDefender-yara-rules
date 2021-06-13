rule Backdoor_Mozi {
   meta:
      description = "Mozi"
      author = "LightDefender"
      date = "2021-06-13"
   strings:
      $s1 = {63 68 6D 6F 64 2B 37 37 37 2B 4D 6F 7A 69 2E 61}
      $s2 = {65 61 6C 6D 3D 22 48 75 61 77 65 69 48 6F 6D 65 47 61 74 65 77 61 79 22 2C 20}
      $s3 = {2D 72 20 2F 4D 6F 7A 69 2E 6D 3B}
      $s4 = {55 73 65 72 2D 41 67 65 6E 74 3A 20 48 65 6C 6C 6F 2C 20 77 6F 72 6C 64}
      $s5 = "loginok" fullword ascii
      $s6 = "GET /Mozi.p HTTP/1.0" fullword ascii
      $s7 = "GET /Mozi.l HTTP/1.0" fullword ascii
      $s8 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1" fullword ascii
      $s9 = "GET /Mozi.r HTTP/1.0" fullword ascii
      $s10 = "GET /Mozi.6 HTTP/1.0" fullword ascii
      $header = {7F 45 4C 46 01 01 01}
   condition:
      $header at 0 and filesize < 500KB and 2 of them
}
