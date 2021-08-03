rule memz_bat {
   meta:
      description = "Geometry dash auto speedhack.bat"
      author = "LightDefender"
      date = "2021-06-13"
      hash1 = "5e2cd213ff47b7657abd9167c38ffd8b53c13261fe22adddea92b5a2d9e320ad"
   strings:
      $s1 = "set v=\"%appdata%\\MEMZ.exe\"" fullword ascii
      $s2 = "echo f=new ActiveXObject(^\"Scripting.FileSystemObject^\");i=f.getFile(^\"x^\").openAsTextStream();>x.js" fullword ascii
      $s3 = "echo z=f.getAbsolutePathName(^\"z.zip^\");o.saveToFile(z);s=new ActiveXObject(^\"Shell.Application^\");>>x.js" fullword ascii
      $s4 = "echo x=new ActiveXObject(^\"MSXml2.DOMDocument^\").createElement(^\"Base64Data^\");x.dataType=^\"bin.base64^\";>>x.js" fullword ascii
      $s5 = "cscript x.js >NUL 2>NUL" fullword ascii
      $s6 = "start \"\" %v%" fullword ascii
      $s7 = "echo x.text=i.readAll();o=new ActiveXObject(^\"ADODB.Stream^\");o.type=1;o.open();o.write(x.nodeTypedValue);>>x.js" fullword ascii
      $s8 = "del %v% >NUL 2>NUL" fullword ascii
   condition:
      uint16(0) == 0x6540 and filesize < 50KB and
      2 of them
}

rule memz_exe {
   meta:
      description = "geometry dash auto speedhack.exe"
      author = "LightDefender"
      date = "2021-06-13"
      hash1 = "a3d5715a81f2fbeb5f76c88c9c21eeee87142909716472f911ff6950c790c24d"
   strings:
      $s1 = "http://answers.microsoft.com/en-us/protect/forum/protect_other-protect_scanning/memz-malwarevirus-trojan-completely-destroying/2" ascii
      $s2 = "http://google.co.ck/search?q=virus.exe" fullword ascii
      $s3 = "http://answers.microsoft.com/en-us/protect/forum/protect_other-protect_scanning/memz-malwarevirus-trojan-completely-destroying/2" ascii
      $s4 = "http://motherboard.vice.com/read/watch-this-malware-turn-a-computer-into-a-digital-hellscape" fullword ascii
      $s5 = "http://google.co.ck/search?q=what+happens+if+you+delete+system32" fullword ascii
      $s6 = "If you are seeing this message without knowing what you just executed, simply press No and nothing will happen." fullword ascii
      $s7 = "DO YOU WANT TO EXECUTE THIS MALWARE, RESULTING IN AN UNUSABLE MACHINE?" fullword ascii
      $s8 = "The software you just executed is considered malware." fullword ascii
      $s9 = "STILL EXECUTE IT?" fullword ascii
      $s10 = "http://google.co.ck/search?q=minecraft+hax+download+no+virus" fullword ascii
      $s11 = "http://google.co.ck/search?q=how+to+download+memz" fullword ascii
      $s12 = "http://google.co.ck/search?q=virus+builder+legit+free+download" fullword ascii
      $s13 = "http://google.co.ck/search?q=bonzi+buddy+download+free" fullword ascii
      $s14 = "http://google.co.ck/search?q=batch+virus+download" fullword ascii
      $s15 = "http://google.co.ck/search?q=facebook+hacking+tool+free+download+no+virus+working+2016" fullword ascii
      $s16 = " - danooct1 2016" fullword ascii
      $x1 = "FUCKED BY THE MEMZ TROJAN" ascii
      $x2 = "//./PhysicalDrive0" ascii
      $x3 = "note.txt"
      $x4 = "BitBlt" fullword ascii
   condition:
      5 of them
}
