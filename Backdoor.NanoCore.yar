rule win_nanocore_w0 {
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/NanoCore"
        maltype = "Remote Access Trojan"
        filetype = "exe"
		source = "https://github.com/mattulm/sfiles_yara/blob/master/malware/NanoCore.yar"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nanocore"
        malpedia_version = "20170517"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $a = "NanoCore"
        $b = "ClientPlugin"
        $c = "ProjectData"
        $d = "DESCrypto"
        $e = "KeepAlive"
        $f = "IPNETROW"
        $g = "LogClientMessage"
		$h = "|ClientHost"
		$i = "get_Connected"
		$j = "#=q"
        $key = {43 6f 24 cb 95 30 38 39}


    condition:
        6 of them
}

rule Backdoor_Nanocore__1 {
   meta:
      description = "NanoCore"
      author = "LightDefender"
      date = "2021-06-13"
   strings:
      $s0 = "$VB$Local_TaskToExecute" fullword ascii
      $s1 = " Barret 2017 - 2021" fullword wide
      $s2 = "LateGet" fullword ascii
      $s3 = "PayloadGet" fullword ascii
      $s4 = "PayloadSet" fullword ascii
      $s5 = "NEWCONNECTION" fullword ascii
      $s6 = "get_ClientDropped" fullword ascii
      $s7 = "_targetFormat" fullword ascii
      $s8 = "FileHistoryStandalone" wide
      $s9 = "\\.tmp$" fullword ascii
      $s10 = "SeShutdownPrivilege" fullword ascii
      
      $x1 = "Microsoft.VisualBasic" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}
