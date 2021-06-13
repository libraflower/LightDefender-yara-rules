rule troj_KillWin {
   meta:
      description = "Trojan.KillWin"
      author = "LightDefender"
      date = "2021-06-13"
   strings:
      $x1 = "cmd /k rd/s/q C:\\Windows\\System32\\Taskmgr.exe" fullword ascii
      $x3 = "taskkill /f /im taskmgr.exe" fullword ascii
      $x4 = "taskkill /f /im explorer.exe" fullword ascii
      $x6 = "cmd /k rd/s/q C:\\Windows\\explorer.exe" fullword ascii
      $x7 = "cmd /k del C:\\WINDOWS\\System32\\*.*/q" fullword ascii
      $s8 = "C:\\Windows\\System32\\Taskmgr.exe" fullword ascii
      $s9 = "cmd /k del C:\\WINDOWS\\*.*/q" fullword ascii
      $s10 = "format.exe c: /q /x" fullword ascii
      $s12 = "format.exe d: /q /x" fullword ascii
      $s13 = "format.exe f: /q /x" fullword ascii
      $s14 = "format.exe e: /q /x" fullword ascii
      $s15 = "C:\\Windows\\explorer.exe" fullword ascii
      $s16 = "cmd /k rd/s/q c:\\" fullword ascii
      $s17 = "cmd /k rd/s/q e:\\" fullword ascii
      $s18 = "cmd /k rd/s/q d:\\" fullword ascii
      $s19 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\tdpipe.sys\\" fullword ascii
      $s20 = "cmd /k del C:\\*.*/q" fullword ascii
      $s21 = "\\d3d9.dll" fullword ascii
      $s24 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\Netlogon\\" fullword ascii
      $s25 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\Netlogon\\" fullword ascii
      $s26 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\vga.sys\\" fullword ascii
      $s27 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\sr.sys\\" fullword ascii
      $s28 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\ip6fw.sys\\" fullword ascii
      $s29 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\sermouse.sys\\" fullword ascii
      $s30 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\rdpcdd.sys\\" fullword ascii
      $s31 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\dmio.sys\\" fullword ascii
      $s32 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\vgasave.sys\\" fullword ascii
      $s33 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\sr.sys\\" fullword ascii
      $s34 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\ipnat.sys\\" fullword ascii
      $s35 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\dmboot.sys\\" fullword ascii
      $s37 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\vgasave.sys\\" fullword ascii
      $s38 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\rdpdd.sys\\" fullword ascii
      $s39 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\dmload.sys\\" fullword ascii
      $s40 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\rdpwd.sys\\" fullword ascii
      $s41 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\dmboot.sys\\" fullword ascii
      $s42 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\vga.sys\\" fullword ascii
      $s43 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\tdtcp.sys\\" fullword ascii
      $s44 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\sermouse.sys\\" fullword ascii
      $s45 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\dmload.sys\\" fullword ascii
      $s46 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\dmio.sys\\" fullword ascii
      $s47 = "    Component %d: %dhx%dv q=%d" fullword ascii
      $s48 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\EventLog\\" fullword ascii
      $s49 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\PCI Configuration\\" fullword ascii
      $s50 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\LmHosts\\" fullword ascii
      $s51 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\PCI Configuration\\" fullword ascii
      $s52 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\EventLog\\" fullword ascii
      $s53 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoLogOff" fullword ascii
      $s54 = " inflate 1.1.4 Copyright 1995-2002 Mark Adler " fullword ascii
      $s56 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\SRService\\" fullword ascii
      $s57 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\termservice\\" fullword ascii
      $s58 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\DcomLaunch\\" fullword ascii
      $s59 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\DcomLaunch\\" fullword ascii
      $s60 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\Streams Drivers\\" fullword ascii
      $s61 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\name" fullword ascii
      $s62 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoRun" fullword ascii
      $s63 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Disableregistrytools" fullword ascii
      $s64 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\SRService\\" fullword ascii
      $s65 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\NtLmSsp\\" fullword ascii
      $s66 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableTaskMgr" fullword ascii
      $s77 = "slmgr /upk" fullword ascii
      $s79 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\System Bus Extender\\" fullword ascii
      $s80 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\Base\\" fullword ascii
      $s81 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\Boot file system\\" fullword ascii
      $s82 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\HelpSvc\\" fullword ascii
      $s83 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoFind" fullword ascii
      $s84 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\NDIS\\" fullword ascii
      $s85 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\Primary disk\\" fullword ascii
      $s86 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\{4D36E96F-E325-11CE-BFC1-08002BE10318}\\" fullword ascii
      $s87 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\{4D36E96A-E325-11CE-BFC1-08002BE10318}\\" fullword ascii
      $s88 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\" fullword ascii
      $s89 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoClose" fullword ascii
      $s90 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\" fullword ascii
      $s91 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\{4D36E973-E325-11CE-BFC1-08002BE10318}\\" fullword ascii
      $s92 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\WinMgmt\\" fullword ascii
      $s93 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\{4D36E97D-E325-11CE-BFC1-08002BE10318}\\" fullword ascii
      $s94 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\AppMgmt\\" fullword ascii
      $s95 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\dmadmin\\" fullword ascii
      $s96 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\AppMgmt\\" fullword ascii
      $s97 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\Boot file system\\" fullword ascii
      $s98 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\{4D36E96B-E325-11CE-BFC1-08002BE10318}\\" fullword ascii
      $s99 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\{4D36E977-E325-11CE-BFC1-08002BE10318}\\" fullword ascii
      $s100 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\PlugPlay" fullword ascii
      $s101 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Folder\\Hidden\\SHOWALL\\CheckedValue" fullword ascii
      $s102 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\{4D36E980-E325-11CE-BFC1-08002BE10318}\\" fullword ascii
      $s103 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\{4D36E96A-E325-11CE-BFC1-08002BE10318}\\" fullword ascii
      $s104 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoSetFolders" fullword ascii
      $s105 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\{36FC9E60-C465-11CF-8056-444553540000}\\" fullword ascii
      $s106 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\NetworkProvider\\" fullword ascii
      $s107 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\NetDDEGroup\\" fullword ascii
      $s108 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\{4D36E969-E325-11CE-BFC1-08002BE10318}\\" fullword ascii
      $s109 = "Software\\Microsoft\\Windows\\CurrentVersion\\Interner Settings\\Zones\\3\\1803" fullword ascii
      $s110 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\Filter\\" fullword ascii
      $s111 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\PNP Filter\\" fullword ascii
      $s112 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\{4D36E96B-E325-11CE-BFC1-08002BE10318}\\" fullword ascii
      $s113 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\RpcSs\\" fullword ascii
      $s114 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoDrives" fullword ascii
      $s115 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoControlPanel" fullword ascii
      $s116 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoRecentDocsMenu" fullword ascii
      $s117 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\Dhcp\\" fullword ascii
      $s118 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\Browser\\" fullword ascii
      $s119 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\Primary disk\\" fullword ascii
      $s120 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\{4D36E977-E325-11CE-BFC1-08002BE10318}\\" fullword ascii
      $s121 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\Messenger\\" fullword ascii
      $s122 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\TDI\\" fullword ascii
      $s123 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\LanmanWorkstation\\" fullword ascii
      $s124 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\HelpSvc\\" fullword ascii
      $s125 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\Boot Bus Extender\\" fullword ascii
      $s126 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\{4D36E967-E325-11CE-BFC1-08002BE10318}\\" fullword ascii
      $s127 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\LanmanServer\\" fullword ascii
      $s128 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoViewContextMenu" fullword ascii
      $s129 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\{4D36E965-E325-11CE-BFC1-08002BE10318}\\" fullword ascii
      $s130 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\dmserver\\" fullword ascii
      $s131 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoFolderOptions" fullword ascii
      $s132 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\{4D36E965-E325-11CE-BFC1-08002BE10318}\\" fullword ascii
      $s133 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\Filter\\" fullword ascii
      $s134 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\AFD\\" fullword ascii
      $s135 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\{71A27CDD-812A-11D0-BEC7-08002BE2092F}\\" fullword ascii
      $s136 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\File system\\" fullword ascii
      $s137 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\WinMgmt\\" fullword ascii
      $s138 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\dmadmin\\" fullword ascii
      $s139 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\{4D36E967-E325-11CE-BFC1-08002BE10318}\\" fullword ascii
      $s140 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoFileMenu" fullword ascii
      $s141 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\NetBIOS\\" fullword ascii
      $s142 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoViewOnDrive" fullword ascii
      $s143 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\{4D36E975-E325-11CE-BFC1-08002BE10318}\\" fullword ascii
      $s144 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\RpcSs\\" fullword ascii
      $s145 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\{745A17A0-74D3-11D0-B6FE-00A0C90F57DA}\\" fullword ascii
      $s146 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\NetMan\\" fullword ascii
      $s147 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\{4D36E969-E325-11CE-BFC1-08002BE10318}\\" fullword ascii
      $s148 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\Tcpip\\" fullword ascii
      $s149 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\{4D36E97B-E325-11CE-BFC1-08002BE10318}\\" fullword ascii
      $s150 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\{4D36E97B-E325-11CE-BFC1-08002BE10318}\\" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and 3 of them
}
