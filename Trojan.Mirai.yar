// From ClamAV
rule Win_Trojan_Mirai_5840677_0
{
    strings:
			$a0 = { 6563686f202d6e6520272573272025732075706e703b202f62696e2f62757379626f782045434348490d0a }

    condition:
        any of them
}
