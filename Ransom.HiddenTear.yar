rule Ransom_HiddenTear_1
{
    meta:
        description = "Open-Source ransomware available on Github since 2015, with many versions in the wild."
        author = "LightDefender"
        date = "2021-06-28"
    strings:
        $s1 = "hidden_tear" fullword ascii
        $s2 = ".locked"
        $s3 = "with hidden tear"
        $s4 = "Send me some bitcoins or kebab"
        $s5 = "\\hidden_tear.pdb" ascii
    condition:
        uint16(0) == 0x5a4d and 3 of them
}

rule Ransom_HiddenTear_2
{
    meta:
        description = "Open-Source ransomware available on Github since 2015, with many versions in the wild."
        author = "LightDefender"
        date = "2021-06-28"
    strings:
        $s1 = "computerName" fullword ascii
        $s2 = "userDir" fullword ascii
        $s3 = "userName" fullword ascii
        $s4 = "AES_Encrypt" fullword ascii
        $s5 = "CreatePassword" fullword ascii
        $op1 = {72????0070 28??00000A 6F??00000A 28??00000A 6F??00000A 26}
        $x1 = "7ab0dd04-43e0-4d89-be59-60a30b766467" nocase ascii wide
    condition:
        uint16(0) == 0x5a4d and (4 of ($s*) or any of ($op*) or any of ($x*))
}
