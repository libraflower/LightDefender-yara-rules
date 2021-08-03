rule Maldoc_Aug_3 {
   meta:
      description = "detects maldoc"
      author = "LightDefender"
      date = "2021-08-03"
      hash1 = "0a4315aced819ab564058480ffeeeb059756030d8c056605f2e0c6fc88b8b2f5"
   strings:
      $s1 = "dwProcessId" ascii
      $s2 = "CreateProcess" ascii
      $s3 = "lpProcessAttributes" ascii
      $s4 = "lpProcessInformationui" fullword ascii
      $s5 = "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS" fullword ascii
      $s6 = "ProcessFoundH" ascii
      $s7 = "objProcessSet" ascii
      $s8 = "PROCESSENTRY32M" fullword ascii
      $s9 = "Project.NewMacros.getPidByName" fullword wide
      $s10 = "PROJECT.NEWMACROS.GETPIDBYNAME" fullword wide
   condition:
      uint16(0) == 0xcfd0 and
      7 of them
}
