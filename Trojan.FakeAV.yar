import "pe"
rule Trojan_Fake_Kaspersky {
   meta:
      description = "RansomeWare"
      date = "2021-07-13"
      author = "LightDefender"
      hash1 = "051db0b4b1055158132cffbfb92d1dfd3fd1c521d2b72aacfc69b102f2cb4253"
   strings:
      $a1 = {00002901002432613534313335392D643538302D346666312D616435342D333330313135663464313433}
      $s1 = "\\\\.\\PhysicalDrive0"
      $s2 = "\\lol.bat"
      $op1 = {027B08000004176F2700000A20B80B00002809000006027B090000046F2800000ADE0326DE00}
   condition:
      pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and (any of ($a*) or all of ($s*) or any of ($op*))
}
