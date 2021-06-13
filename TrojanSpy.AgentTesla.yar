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

  
rule AgentTesla
{
    meta:
        author = "kevoreilly"
        description = "AgentTesla Payload"
        cape_type = "AgentTesla Payload"
    strings:
        $string1 = "smtp" wide
        $string2 = "appdata" wide
        $string3 = "76487-337-8429955-22614" wide
        $string4 = "yyyy-MM-dd HH:mm:ss" wide
        //$string5 = "%site_username%" wide
        $string6 = "webpanel" wide
        $string7 = "<br>UserName&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;:" wide
        $string8 = "<br>IP Address&nbsp;&nbsp;:" wide

        $agt1 = "IELibrary.dll" ascii
        $agt2 = "C:\\Users\\Admin\\Desktop\\IELibrary\\IELibrary\\obj\\Debug\\IELibrary.pdb" ascii
        $agt3 = "GetSavedPasswords" ascii
        $agt4 = "GetSavedCookies" ascii
    condition:
        uint16(0) == 0x5A4D and (all of ($string*) or 3 of ($agt*))
}

rule MALW_Agenttesla
{
    meta:
        description = "Detecting HTML strings used by Agent Tesla malware"
        author = "Stormshield"
        reference = "https://thisissecurity.stormshield.com/2018/01/12/agent-tesla-campaign/"
        version = "1.0"

    strings:
        $html_username    = "<br>UserName&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;: " wide ascii
        $html_pc_name     = "<br>PC&nbsp;Name&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;: " wide ascii
        $html_os_name     = "<br>OS&nbsp;Full&nbsp;Name&nbsp;&nbsp;: " wide ascii
        $html_os_platform = "<br>OS&nbsp;Platform&nbsp;&nbsp;&nbsp;: " wide ascii
        $html_clipboard   = "<br><span style=font-style:normal;text-decoration:none;text-transform:none;color:#FF0000;><strong>[clipboard]</strong></span>" wide ascii

    condition:
        3 of them
}

rule agenttesla_smtp_variant {

    meta:
        author = "J from THL <j@techhelplist.com> with thx to @Fumik0_ !!1!"
        date = "2018/2"
	reference1 = "https://www.virustotal.com/#/file/1198865bc928a7a4f7977aaa36af5a2b9d5a949328b89dd87c541758516ad417/detection"
	reference2 = "https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/tspy_negasteal.a"
	reference3 = "Agent Tesla == negasteal -- @coldshell"
	version = 1
        maltype = "Stealer"
        filetype = "memory"

    strings:
		$a = "type={"
		$b = "hwid={"
		$c = "time={"
		$d = "pcname={"
		$e = "logdata={"
		$f = "screen={"
		$g = "ipadd={"
		$h = "webcam_link={"
		$i = "screen_link={"
		$j = "site_username={"
		$k = "[passwords]"

    condition:
        6 of them
}

rule MALWARE_Win_AgentTeslaV2 {
    meta:
        author = "ditekSHen"
        description = "AgenetTesla Type 2 Keylogger payload"
    strings:
        $s1 = "get_kbHook" ascii
        $s2 = "GetPrivateProfileString" ascii
        $s3 = "get_OSFullName" ascii
        $s4 = "get_PasswordHash" ascii
        $s5 = "remove_Key" ascii
        $s6 = "FtpWebRequest" ascii
        $s7 = "logins" fullword wide
        $s8 = "keylog" fullword wide
        $s9 = "1.85 (Hash, version 2, native byte-order)" wide

        $cl1 = "Postbox" fullword ascii
        $cl2 = "BlackHawk" fullword ascii
        $cl3 = "WaterFox" fullword ascii
        $cl4 = "CyberFox" fullword ascii
        $cl5 = "IceDragon" fullword ascii
        $cl6 = "Thunderbird" fullword ascii
    condition:
        (uint16(0) == 0x5a4d and 6 of ($s*)) or (6 of ($s*) and 2 of ($cl*))
}


rule MALWARE_Win_AgentTeslaV3 {
    meta:
      author = "ditekSHen"
      description = "AgentTeslaV3 infostealer payload"
    strings:
      $s1 = "get_kbok" fullword ascii
      $s2 = "get_CHoo" fullword ascii
      $s3 = "set_passwordIsSet" fullword ascii
      $s4 = "get_enableLog" fullword ascii
      $s5 = "bot%telegramapi%" wide
      $s6 = "KillTorProcess" fullword ascii 
      $s7 = "GetMozilla" ascii
      $s8 = "torbrowser" wide
      $s9 = "%chatid%" wide
      $s10 = "logins" fullword wide
      $s11 = "credential" fullword wide
      $s12 = "AccountConfiguration+" wide
      $s13 = "<a.+?href\\s*=\\s*([\"'])(?<href>.+?)\\1[^>]*>" fullword wide

      $g1 = "get_Clipboard" fullword ascii
      $g2 = "get_Keyboard" fullword ascii
      $g3 = "get_Password" fullword ascii
      $g4 = "get_CtrlKeyDown" fullword ascii
      $g5 = "get_ShiftKeyDown" fullword ascii
      $g6 = "get_AltKeyDown" fullword ascii

      $m1 = "yyyy-MM-dd hh-mm-ssCookieapplication/zipSCSC_.jpegScreenshotimage/jpeg/log.tmpKLKL_.html<html></html>Logtext/html[]Time" ascii
      $m2 = "%image/jpg:Zone.Identifier\\tmpG.tmp%urlkey%-f \\Data\\Tor\\torrcp=%PostURL%127.0.0.1POST+%2B" ascii
      $m3 = ">{CTRL}</font>Windows RDPcredentialpolicyblobrdgchrome{{{0}}}CopyToComputeHashsha512CopySystemDrive\\WScript.ShellRegReadg401" ascii
      $m4 = "%startupfolder%\\%insfolder%\\%insname%/\\%insfolder%\\Software\\Microsoft\\Windows\\CurrentVersion\\Run%insregname%SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\RunTruehttp" ascii
      $m5 = "\\WindowsLoad%ftphost%/%ftpuser%%ftppassword%STORLengthWriteCloseGetBytesOpera" ascii
    condition:
      (uint16(0) == 0x5a4d and (8 of ($s*) or (6 of ($*) and all of ($g*)))) or (2 of ($m*))
}
