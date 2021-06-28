rule Ransom_HiddenTear
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
        uint16(0) == 0x5a4d and any of them
}
