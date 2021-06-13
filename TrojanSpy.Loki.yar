rule spy_loki {
   meta:
      description = "TrojanSpy.Loki"
      author = "LightDefender"
      date = "2021-06-13"
      hash1 = "10a7285287f351ae201ec72dea640fd1eabf1a7c54955f9fbd6de4e4a5309642"
   strings:
      $s1 = "sheFDll32.dll" fullword ascii
      $s2 = "flfjaseriernechasmykaramboleren.exe" fullword wide
      $s3 = "\\MSINFO32.EXE" fullword wide
      $s4 = "PZwSetInformationProcess" fullword ascii
      $s5 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB" fullword ascii
      $s6 = "overhardnessekstrabevillingernesti" fullword ascii
      $s7 = "The temp. path is " fullword wide
      $s8 = "FDkernel32" fullword ascii
      $s9 = "CERTERT.kpd" fullword wide
      $s10 = "dullestmisseemgruesomelysubdivida" fullword ascii
      $s11 = "historiometrykontooverfrslerdisrup" fullword ascii
      $s12 = "departementerstwatsevolvementsaar" fullword ascii
      $s13 = "topfartsmedellinpyrolaceaebedrive" fullword ascii
      $s14 = "jerezlssetsfantasiestaabeligeobje" fullword ascii
      $s15 = "facetslebetantipatrioticdasjohn" fullword ascii
      $s16 = "regionarybookkeepslystendesumme" fullword ascii
      $s17 = "delsindballelssernesocialraadgive" fullword ascii
      $s18 = "biciliatemockspersimmonevenmetefl" fullword ascii
      $s19 = "nomarchyhermelinsskindetsspidsbel" fullword ascii
      $s20 = "aaenchitinogenoushrgulesidevaegge" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      5 of them
}
