rule TrojanDownloader_GuLoader {
   meta:
      description = "TrojanDownloader.GuLoader"
      author = "LightDefender"
      date = "2021-06-25"
      hash1 = "4ee78cf82b434634075e121ebbe7dce9aa4b0a18c04f54f70d84c891f7a56507"
      hash2 = "2cad3c6af2167827f44f2d53c36b8aed25c361cbe90b030a024dd13ecc649d7f"
   strings:
      $op1 = {558BEC83EC0C688613400064A100000000506489}
      $op2 = {8B450889510889953CFBFFFF8B9540FBFFFF5089}
      $op3 = {CCCCCCCCCCCCCCCCCCCCCCCC558BEC83EC0C6886}
   condition:
      uint16(0) == 0x5a4d and all of them
 }

rule MAL_crime_win32_loader_guloader_1_experimental {
   meta:
      description = "Detects injected GuLoader shellcode bin"
      author = "@VK_Intel"
      reference = "https://twitter.com/VK_Intel/status/1257206565146370050"
      tlp = "white"
      date = "2020-05-04"
   strings:
      $djib2_hash = { f8 8b ?? ?? ?? ba 05 15 00 00 89 d3 39 c0 c1 e2 05 81 ff f6 62 f1 87 01 da 0f ?? ?? d9 d0 01 da 83 c6 02 66 ?? ?? ?? 75 ?? c2 04 00}
      $nt_inject_loader = {8b ?? ?? ba 44 1a 0e 9e 39 d2 e8 ?? ?? ?? ?? 89 ?? ?? 8b ?? ?? f8 ba d0 e0 8b 30 e8 ?? ?? ?? ?? d9 d0 89 ?? ?? d9 d0 81 fb 20 af 00 00 8b ?? ?? 39 c9 ba 92 a7 f3 95 e8 ?? ?? ?? ?? 89 ?? ?? 8b ?? ?? 39 d2 ba d0 20 2e d0 e8 ?? ?? ?? ?? 89 ?? ?? f8 8b ?? ?? ba 6a 19 1f 23 d9 d0 e8 ?? ?? ?? ?? d9 d0 89 ?? ?? 81 fb e4 8c 00 00 39 c9 8b ?? ?? ba 19 50 9c c2 e8 ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 39 d2 8b ?? ?? fc ba 3d 13 8e 8b e8 ?? ?? ?? ?? d9 d0 89 ?? ?? f8 8b ?? ?? ba 30 3d 7b 2c e8 ?? ?? ?? ??}
   condition:
      uint16(0) == 0x5a4d and all of them 
}

rule Guloader
{
    meta:
        author = "kevoreilly"
        description = "Guloader bypass"
        //cape_options = "bp0=$trap0,bp0=$trap1+4,action0=skip,bp1=$trap2+11,bp1=$trap3+19,action1=skip,bp2=$antihook,action2=goto:ntdll::NtAllocateVirtualMemory,count=0"
    strings:
        $trap0 = {0F 85 [2] FF FF 81 BD ?? 00 00 00 [2] 00 00 0F 8F [2] FF FF 39 D2 83 FF 00}
        $trap1 = {49 83 F9 00 75 [1-20] 83 FF 00 [2-6] 81 FF}
        $trap2 = {39 CB 59 01 D7 49 85 C8 83 F9 00 75 B3}
        $trap3 = {61 0F AE E8 0F 31 0F AE E8 C1 E2 20 09 C2 29 F2 83 FA 00 7E CE C3}
        $antihook = {FF 34 08 [0-300] 8F 04 0B [0-300] 83 F9 18 [0-300] FF E3}
    condition:
        2 of them
}

rule GuloaderB
{
    meta:
        author = "kevoreilly"
        description = "Guloader bypass 2021 Edition"
        //cape_options = "bp0=$trap0,action0=ret,bp1=$trap1,action1=ret:2,bp2=$antihook,action2=goto:ntdll::NtAllocateVirtualMemory,count=0,bp3=$trap2+7,action3=skip"
    strings:
        $trap0 = {81 C6 00 10 00 00 [0-88] 81 FE 00 F0 [2] 0F 84 [2] 00 00}
        $trap1 = {31 FF [0-128] (B9|C7 85 F8 00 00 00) 60 5F A9 00}
        $antihook = {FF 34 08 [0-360] 8F 04 0B [0-360] 83 F9 18 [0-460] FF E3}
        $trap2 = {83 BD 9C 00 00 00 00 0F 85 [2] 00 00}
    condition:
        2 of them
}
