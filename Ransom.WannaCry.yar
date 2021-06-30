rule Ransom_WannaDecryptor: WannaDecryptor
{
        meta:
                description = "Detection for common strings of WannaDecryptor"
 
        strings:
                $id1 = "taskdl.exe" fullword ascii
                $id2 = "taskse.exe" fullword ascii
                $id3 = "r.wnry"
                $id4 = "s.wnry"
                $id5 = "t.wnry"
                $id6 = "u.wnry"
                $id7 = "msg/m_"
 
        condition:
                uint16(0) == 0x5a4d and 3 of them
}

rule Ransom_WannaCry_Variant_June_30 {
   meta:
      description = "Ransom.WannaCry (FlyStudio)"
      author = "LightDefender"
      date = "2021-06-30"
      hash1 = "fa3ebf23620bbafc369a8af1d2a98eca52bf8b5e94707b17eb0771c2138d9250"
   strings:
      $s1 = {00 57 61 6E 6E 61 43 72 79 20 33 2E 30 20 20 40 50 6C 65 61 73 65 5F 52 65 61 64 5F 4D 65 40 00}
      $s2 = {C7 EB D6 A7 B8 B6 31 B8 F6 B1 C8 CC D8 B1 D2 B5 BD D5 E2 B5 D8 D6}
      $s3 = "dzclsh@gmail.com" ascii
      $s4 = {BD AB BD E2 C3 DC C4 FA B5 C4 CB F9 D3 D0 CE C4}
      $s5 = {D2 AA D6 D8 C3 FC C3 FB BC D3 C3 DC B5 C4 CE C4}
      $s6 = {00 00 43 68 65 63 6B 20 50 61 79 6D 65 6E 74 D0}
      $flystudio = {7cfb7edf68385fc3652f63015e93}
   condition:
      uint16(0) == 0x5a4d and any of ($s*) and $flystudio
}
