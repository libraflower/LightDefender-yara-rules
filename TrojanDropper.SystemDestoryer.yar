rule TrojanDropper_SystemDestoryer {
   meta:
      description = "TrojanDropper.SystemDestoryer"
      author = "LightDefender"
      date = "2021-08-02"
      hash1 = "66320581f82cf36ea58d80aa1d529614d15a8e9e91e05d787480a3b05257d887"
      hash2 = "b90fac39faeb6ce7e25aedb4b96940bcc5178dbcf0bec081bb9f88943000b514"
   strings:
      $x1 = "del /f /q %appdata%\\" nocase
      $x2 = "certutil -f -decode %0 %appdata%" nocase
      $s3 = "del /f /q %appdata%" nocase
      $s4 = "echo Dim intOptions, objShell, objSource, objTarget" nocase ascii
      $s5 = "echo Set objTarget = objShell.NameSpace(myTargetDir)" nocase ascii
      $s6 = "echo Extract \"%appdata%\\virus.zip\", \"%appdata%\"" nocase ascii
      $s7 = "echo Set objTarget = Nothing" nocase ascii
      $s8 = "echo Sub Extract( ByVal myZipFile, ByVal myTargetDir )" nocase ascii
      $s9 = "echo objTarget.CopyHere objSource, intOptions" nocase ascii
      $s10 = "if %number% == 5 start /max all.bat&exit" fullword ascii
      $s11 = "if %number% == 4 start /max net1.bat&exit" fullword ascii
      $s12 = "if %number% == 2 start /max reg1.bat&exit" fullword ascii
      $s13 = "if %number% == 3 start /max Boot.bat&exit" fullword ascii
      $s14 = "if %number% == 1 start /max del1.bat&exit" fullword ascii
      $s15 = "cd %appdata%" fullword ascii
      $s16 = "%1 start \"\" mshta vbscript:createobject(\"shell.application\").shellexecute(\"\"\"%~0\"\"\",\"::\",,\"runas\",1)(window.close)" ascii
      $s17 = "if exist \"%SystemRoot%\\SysWOW64\" path %path%;%windir%\\SysNative;%SystemRoot%\\SysWOW64;%~dp0" fullword ascii
      $s18 = "echo Set objSource = objShell.NameSpace(myZipFile).Items>>jieya.VBS" fullword ascii
      $s19 = "echo Set objShell = Nothing>>jieya.VBS" fullword ascii
   condition:
      1 of ($x*) and 6 of them
}
