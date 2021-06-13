rule win_agent_tesla_w0 {
    meta:
        author = "InQuest Labs"
        source = "https://www.inquest.net"
        created = "05/18/2018"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.agent_tesla"
        malpedia_version = "20190731"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $s0 = "SecretId1" ascii
        $s1 = "#GUID" ascii
        $s2 = "#Strings" ascii
        $s3 = "#Blob" ascii
        $s4 = "get_URL" ascii
        $s5 = "set_URL" ascii
        $s6 = "DecryptIePassword" ascii
        $s8 = "GetURLHashString" ascii
        $s9 = "DoesURLMatchWithHash" ascii

        $f0 = "GetSavedPasswords" ascii
        $f1 = "IESecretHeader" ascii
        $f2 = "RecoveredBrowserAccount" ascii
        $f4 = "PasswordDerivedBytes" ascii
        $f5 = "get_ASCII" ascii
        $f6 = "get_ComputerName" ascii
        $f7 = "get_WebServices" ascii
        $f8 = "get_UserName" ascii
        $f9 = "get_OSFullName" ascii
        $f10 = "ComputerInfo" ascii
        $f11 = "set_Sendwebcam" ascii
        $f12 = "get_Clipboard" ascii
        $f13 = "get_TotalFreeSpace" ascii
        $f14 = "get_IsAttached" ascii

        $x0 = "IELibrary.dll" ascii wide
        $x1 = "webpanel" ascii wide nocase
        $x2 = "smtp" ascii wide nocase

        $v5 = "vmware" ascii wide nocase
        $v6 = "VirtualBox" ascii wide nocase
        $v7 = "vbox" ascii wide nocase
        $v9 = "avghookx.dll" ascii wide nocase

        $pdb = "IELibrary.pdb" ascii
    condition:
        (
            (
                5 of ($s*) or
                7 of ($f*)
            ) and
            all of ($x*) and
            all of ($v*) and
            $pdb
        )
}

rule win_agent_tesla_w1 {
    meta:
        description = "Detect Agent Tesla based on common .NET code sequences"
        author = "govcert_ch"
        date = "20200429"
        hash = "2b68a3f88fbd394d572081397e3d8d349746a88e3e67a2ffbfac974dd4c27c6a"
        hash = "abadca4d00c0dc4636e382991e070847077c1d19d50153487da791d3be9cc401"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.agent_tesla"
        malpedia_version = "20200506"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 20 ?? ?? ?? ?? 61 25 FE 0E 01 00 20 05 00 00 00 5E 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 38 51 00 00 00}
        $sequence_1 = { 20 ?? ?? ?? ?? 61 25 FE 0E 06 00 20 03 00 00 00 5E 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 38 1C 00 00 00 }
        $sequence_2 = { 04 02 7B 33 04 00 04 03 8F 36 00 00 02 7B 38 04 00 04 8E B7 3F 21 00 00 00 20 ?? ?? ?? ?? 38 97 FF FF FF }

    condition:
        any of them
}
