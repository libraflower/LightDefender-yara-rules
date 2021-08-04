rule Trojan_BreakWin {
   meta:
      description = "Trojan.BreakWin"
      author = "LightDefender"
      reference = "https://labs.sentinelone.com/meteorexpress-mysterious-wiper-paralyzes-iranian-trains-with-epic-troll/"
      date = "2021-08-04"
      hash1 = "2aa6e42cb33ec3c132ffce425a92dfdb5e29d8ac112631aec068c8a78314d49b"
   strings:
      $x1 = "C:\\Windows\\System32\\cmd.exe" fullword wide
      $x2 = "Process created successfully. Executed command: %s." fullword wide
      $x3 = "Could not create impersonated process. Command: %s, error code: %s." fullword wide
      $x4 = "Could not create process. Command: %s, error code: %s." fullword wide
      $x5 = "bcdedit.exe" fullword ascii
      $s6 = "Getting new winlogon session failed. Attempts: %s/%s" fullword wide
      $s7 = "icacls.exe \"C:\\Windows\\Web\\Screen\" /grant System:(OI)(CI)F /T" fullword ascii
      $s8 = "icacls.exe \"C:\\ProgramData\\Microsoft\\Windows\\SystemData\" /grant System:(OI)(CI)F /T" fullword ascii
      $s9 = "icacls.exe \"C:\\ProgramData\\Microsoft\\Windows\\SystemData\" /grant Administrators:(OI)(CI)F /T" fullword ascii
      $s10 = "takeown.exe /F \"C:\\ProgramData\\Microsoft\\Windows\\SystemData\" /R /A /D Y" fullword ascii
      $s11 = "Could not get process exit code. Error code: %s." fullword wide
      $s12 = "icacls.exe \"C:\\Windows\\Web\\Screen\" /grant Administrators:(OI)(CI)F /T" fullword ascii
      $s13 = "attempted to access encrypted file in offset %s, but it only supports offset 0" fullword wide
      $s14 = "takeown.exe /F \"C:\\Windows\\Web\\Screen\" /R /A /D Y" fullword ascii
      $s15 = "Reached maximal attempts of getting a new winlogon token" fullword wide
      $s16 = "Failed creating processes snapshot, process name: %s, error code %s." fullword wide
      $s17 = "Failed to query process info from snapshot. Process name: %s, error code: %s." fullword wide
      $s18 = "Failed opening process, process name: %s, error code %s." fullword wide
      $s19 = "Failed to open process. Pid: %s, error code: %s" fullword wide
      $s20 = "Failed to terminate process. Pid: %s, error code: %s" fullword wide
   condition:
      uint16(0) == 0x5a4d and
      (( 1 of ($x*) and 4 of them ) or 8 of them )
}
