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
