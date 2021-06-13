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

rule spy_agenttesla {
   meta:
      description = "TrojanSpy.AgentTesla"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-05-17"
      hash1 = "3dd0ab716a91895df7788197ba7527c9461432a1a35bdec48c6aabda435e0c43"
      hash2 = "f51957a2b4ed970d1a437ca3143f490c13e6311a8f9caea88b4406404aa0fe63"
      hash3 = "6d7571b2d3d4799ba199d0c56ae231b3b1078387ae1ecea2218171ae36fd4881"
      hash4 = "cde7c4f503fc19bc115eed58a703ca6f729b1f4a017163dd36772b29f24351dd"
   strings:
      $s0 = "PublicEncryptionPassword" fullword ascii /* score: '20.00'*/
      $s1 = "GetElapsedCompleteYearsFromDates" fullword ascii /* score: '17.00'*/
      $s2 = "GetGuidTempFileName" fullword ascii /* score: '16.00'*/
      $s3 = "get_subscription_type" fullword ascii /* score: '15.00'*/
      $s4 = "ProcessFilename" fullword ascii /* score: '15.00'*/
      $s5 = "GetAccountForEmailAddress" fullword ascii /* score: '15.00'*/
      $s6 = "ProcessFolderName" fullword ascii /* score: '15.00'*/
      $s7 = "FromStringToPreventSQLInjection" fullword ascii /* score: '14.00'*/
      $s8 = "GetLogEntryTypeName" fullword ascii /* score: '14.00'*/
      $s9 = "DataReaderGetIntegerSafeAsNull" fullword ascii /* score: '12.00'*/
      $s10 = "DataReaderGetString" fullword ascii /* score: '12.00'*/
      $s11 = "DataReaderGetBooleanSafeAsNull" fullword ascii /* score: '12.00'*/
      $s12 = "DataReaderGetLong" fullword ascii /* score: '12.00'*/
      $s13 = "DataReaderGetShortSafeAsNull" fullword ascii /* score: '12.00'*/
      $s14 = "DataReaderGetIntegerSafeAsMinValue" fullword ascii /* score: '12.00'*/
      $s15 = "DataReaderGetStringSafeAsNull" fullword ascii /* score: '12.00'*/
      $s16 = "SMTPAddress" fullword ascii /* score: '12.00'*/
      $s17 = "DataReaderGetShort" fullword ascii /* score: '12.00'*/
      $s18 = "DataReaderGetDateTime" fullword ascii /* score: '12.00'*/
      $s19 = "set_SmtpAddress" fullword ascii /* score: '12.00'*/
      $s20 = "DataReaderGetByte" fullword ascii /* score: '12.00'*/
      $s21 = "_SmtpAddress" fullword ascii /* score: '12.00'*/
      $s22 = "46696C65416363657373" wide /* hex encoded string 'FileAccess' */
      $s23 = "GetNeighbourAt" fullword ascii /* score: '14.00'*/
      $s24 = "GetAccountForEmailAddress" fullword ascii /* score: '15.00'*/
      $s25 = "ProcessFolderName" fullword ascii /* score: '15.00'*/
      $s26 = "494D65737361676553696E6B" wide /* score: '17.00'*/ /* hex encoded string 'IMessageSink' */
      $s27 = "_targetFormat" fullword ascii /* score: '14.00'*/
      $s28 = "get_PLogin" fullword ascii /* score: '17.00'*/
      $s29 = "Failed to get the desktop shell folder" fullword wide /* score: '20.00'*/
      $s30 = " Twometer 2020 - 2021" fullword wide /* score: '12.00'*/
      $s31 = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*" fullword wide /* score: '11.00'*/
      $s32 = "OWNERDRAW" fullword ascii /* base64 encoded string '9cDD4@' */ /* score: '16.50'*/
      $s33 = "RETURNCMD" fullword ascii /* score: '9.50'*/
      $s34 = "get_Download" fullword ascii /* score: '15.00'*/
      $s35 = "User_Password" fullword ascii /* score: '12.00'*/
      $s36 = "_TargetSite" fullword ascii /* score: '14.00'*/
      $s37 = "IELibrary.pdb"
      $s38 = "Download_Click" fullword ascii /* score: '10.00'*/
      $s39 = "                taskkill /f /im explorer.exe" fullword ascii /* score: '26.00'*/
      $s40 = "%HOMEDRIVE%\\Users\\Default\\AppData\\Local\\Microsoft\\Windows\\WinX" fullword wide /* score: '25.00'*/

      $op0 = { 01 ff 02 ff 7f 04 ff ff ff 7f 01 fe 02 fe 7f 04 }
      $op1 = { 01 00 34 35 00 1c 2d 00 00 01 1b 30 03 00 56 }
      $op2 = { 02 1d 6f 33 01 00 0a 13 08 12 08 28 34 01 00 0a }
      $op3 = { fe 01 13 34 11 34 2c 07 1f 61 13 0a 00 2b 06 00 }
      $op4 = { 16 08 be 09 bf 0e 02 00 34 22 }
      $op5 = { 11 18 b8 2f 0a 09 03 00 34 28 }
      $op6 = { 16 2a 02 15 7d 01 00 00 04 02 20 5d f9 34 53 7d }
      $op7 = { 2b 00 00 11 02 7b 34 00 00 04 0a 06 2a }
      $op8 = { 04 00 00 11 03 02 7b 34 00 00 04 28 d1 00 00 0a }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 16 of them ) and 3 of ($op*)
      ) or ( all of them )
}

rule spy_agenttesla2 {
   meta:
      description = "TrojanSpy.AgentTesla"
      author = "LightDefender"
      date = "2021-06-13"
   strings:
      $s0 = "set_passwordIsSet" fullword ascii
      $s1 = "PublicEncryptionPassword" fullword ascii
      $s2 = "get_username" fullword ascii
      $s3 = "get_User_Password" fullword ascii
      $s4 = "IsPasswordNull" fullword ascii
      $s5 = "DecryptIePassword" ascii
      $s6 = "SMTPAddress" fullword ascii
      $s7 = " Twometer 2020 - 2021" fullword wide
      $s8 = "set_SmtpAddress" fullword ascii
      $s9 = "IELibrary.pdb" ascii
      $s10 = "_TargetSite" fullword ascii
      $s11 = "get_PasswordHash" ascii
      $s12 = "GetSavedPasswords" ascii
      $s13 = "set_passwordIsSet" fullword ascii
      $s14 = "torbrowser"
      $s15 = "1.85 (Hash, version 2, native byte-order)" wide
      $s16 = "get_PLogin" fullword ascii
      $s17 = "get_Clipboard" fullword ascii
      $s18 = "46696C65416363657373" wide
      $s19 = "RETURNCMD" fullword ascii
      $s20 = "get_txtconfirm_passwd" fullword ascii
      $s21 = "get_btnlogin" fullword ascii
      $s22 = "_LogWarning" fullword ascii
      $s23 = "get_txtpassword" fullword ascii
      $s24 = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*" fullword wide
      $s25 = "get_chkboxpasswd" fullword ascii
      $s26 = "TopdownDll" fullword wide
      
      $x0 = "#GUID" ascii
      $x1 = "#Strings" ascii
      $x2 = "#Blob" ascii
      $x3 = "Microsoft.VisualBasic" ascii
      $x4 = "16.0.0.0" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and 8 of them) or ( all of them )
 }

rule Agenttesla_telegram_bin

{
    meta:
        author = "James_inthe_box"
        reference = "https://app.any.run/tasks/b4ceef1e-a649-44b7-9e0c-e53c3ab05354"
        date = "2020/08"
        maltype = "RAT"

    strings:
        $stringset31 = "OperatingSystemName"
        $stringset32 = "ProcessorName"
        $stringset33 = "AmountOfMemory"
        $stringset34 = "VideocardName"
        $stringset35 = "VideocardMem"
        $stringset36 = "Password"
        $stringset37 = "Mozilla"
        $stringset38 = "Postbox"
        $stringset39 = "Thunderbird"
        $stringset311 = "SeaMonkey"
        $stringset312 = "Flock"
        $stringset313 = "BlackHawk"
        $stringset314 = "CyberFox"
        $stringset315 = "KMeleon"
        $stringset316 = "IceCat"
        $stringset317 = "PaleMoon"
        $stringset318 = "IceDragon"
        $stringset319 = "WaterFox"
        $stringset320 = "WinSCP"
        $stringset321 = "api.telegram.org"
    condition:
        14 of ($stringset3*) and filesize < 800KB
}

rule AgentTesla_telegram_mem

{
    meta:
        author = "James_inthe_box"
        reference = "https://app.any.run/tasks/b4ceef1e-a649-44b7-9e0c-e53c3ab05354"
        date = "2020/08"
        maltype = "RAT"

    strings:
        $stringset31 = "OperatingSystemName"
        $stringset32 = "ProcessorName"
        $stringset33 = "AmountOfMemory"
        $stringset34 = "VideocardName"
        $stringset35 = "VideocardMem"
        $stringset36 = "Password"
        $stringset37 = "Mozilla"
        $stringset38 = "Postbox"
        $stringset39 = "Thunderbird"
        $stringset311 = "SeaMonkey"
        $stringset312 = "Flock"
        $stringset313 = "BlackHawk"
        $stringset314 = "CyberFox"
        $stringset315 = "KMeleon"
        $stringset316 = "IceCat"
        $stringset317 = "PaleMoon"
        $stringset318 = "IceDragon"
        $stringset319 = "WaterFox"
        $stringset320 = "WinSCP"
        $stringset321 = "api.telegram.org"
    condition:
        14 of ($stringset3*) and filesize > 800KB
}
