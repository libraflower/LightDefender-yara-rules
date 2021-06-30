rule QuasarRAT {
   meta:
      description = "QuasarRat"
      author = "LightDefender"
      date = "2021-06-13"
      hash1 = "38038560199f5d1da23f83e933492a1f5e6c010b8289f6fdae2e1adbec839a12"
   strings:
      $x1 = "PGma.System.MouseKeyHook, Version=5.6.130.0, Culture=neutral, PublicKeyToken=null" fullword ascii
      $x2 = "DQuasar.Common, Version=1.4.0.0, Culture=neutral, PublicKeyToken=null" fullword ascii
      $s3 = "Process already elevated." fullword wide
      $s4 = "get_PotentiallyVulnerablePasswords" fullword ascii
      $s5 = "GetKeyloggerLogsDirectoryResponse" fullword ascii
      $s6 = "System.Collections.Generic.IEnumerable<Gma.System.MouseKeyHook.KeyPressEventArgsExt>.GetEnumerator" fullword ascii
      $s7 = "System.Collections.Generic.IEnumerator<Quasar.Common.Models.FileChunk>.get_Current" fullword ascii
      $s8 = "GetKeyloggerLogsDirectory" fullword ascii
      $s9 = "System.Collections.Generic.IEnumerator<Gma.System.MouseKeyHook.KeyPressEventArgsExt>.get_Current" fullword ascii
      $s10 = "set_PotentiallyVulnerablePasswords" fullword ascii
      $s11 = "Oprotobuf-net, Version=2.4.0.0, Culture=neutral, PublicKeyToken=257b51d87d2e4d67" fullword ascii
      $s12 = "potentiallyVulnerablePasswords" fullword ascii
      $s13 = "<PotentiallyVulnerablePasswords>k__BackingField" fullword ascii
      $s14 = "=Client, Version=1.4.0.0, Culture=neutral, PublicKeyToken=null" fullword ascii
      $s15 = "get_DismissedBreachAlertsByLoginGuid" fullword ascii
      $s16 = "GetProcessesResponse" fullword ascii
      $s17 = "BQuasar.Client.Extensions.RegistryKeyExtensions+<GetKeyValues>d__15" fullword ascii
      $s18 = "Opera Software\\Opera Stable\\Login Data" fullword wide
      $s19 = "https://tools.keycdn.com/geo.json" fullword wide
      $s20 = "Are you mixing protobuf-net and protobuf-csharp-port? See https://stackoverflow.com/q/11564914/23354; type: " fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule QuasarRat2 {
   meta:
      description = "QuasarRAT"
      author = "LightDefender"
      date = "2021-06-13"
      hash1 = "ac14bf805d1796f1463b5f27b79496dab9a07f5bd50336628bcfbdc2dc996acf"
      hash2 = "38038560199f5d1da23f83e933492a1f5e6c010b8289f6fdae2e1adbec839a12"
      hash3 = "ba1a9d2896a18d3f95fb6fb7f94be8adcc60f76a7b5bb8b3c9401c5c64842843"
   strings:
      $s1 = "encryptedUsername" fullword ascii
      $s2 = "hostname" fullword ascii /* Goodware String - occured 84 times */
      $s3 = "Internet Explorer" fullword wide /* Goodware String - occured 518 times */
      $s4 = "mozglue.dll" fullword wide /* Goodware String - occured 1 times */
      $s5 = "nss3.dll" fullword wide /* Goodware String - occured 4 times */
      $s6 = "encryptedPassword" fullword ascii /* Goodware String - occured 5 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them )
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-04-07
   Identifier: Quasar RAT
*/

/* Rule Set ----------------------------------------------------------------- */

rule Quasar_RAT_1 {
   meta:
      description = "Detects Quasar RAT"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf"
      date = "2017-04-07"
      hash1 = "0774d25e33ca2b1e2ee2fafe3fdbebecefbf1d4dd99e6460f0bc8713dd0fd740"
      hash2 = "1ce40a89ef9d56fd32c00db729beecc17d54f4f7c27ff22f708a957cd3f9a4ec"
      hash3 = "515c1a68995557035af11d818192f7866ef6a2018aa13112fefbe08395732e89"
      hash4 = "f08db220df716de3d4f63f3007a03f902601b9b32099d6a882da87312f263f34"
   strings:
      $s1 = "DoUploadAndExecute" fullword ascii
      $s2 = "DoDownloadAndExecute" fullword ascii
      $s3 = "DoShellExecute" fullword ascii
      $s4 = "set_Processname" fullword ascii

      $op1 = { 04 1e fe 02 04 16 fe 01 60 }
      $op2 = { 00 17 03 1f 20 17 19 15 28 }
      $op3 = { 00 04 03 69 91 1b 40 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and all of ($s*) or all of ($op*) )
}

rule Quasar_RAT_2 {
   meta:
      description = "Detects Quasar RAT"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf"
      date = "2017-04-07"
      super_rule = 1
      hash1 = "0774d25e33ca2b1e2ee2fafe3fdbebecefbf1d4dd99e6460f0bc8713dd0fd740"
      hash2 = "515c1a68995557035af11d818192f7866ef6a2018aa13112fefbe08395732e89"
      hash3 = "f08db220df716de3d4f63f3007a03f902601b9b32099d6a882da87312f263f34"
   strings:
      $x1 = "GetKeyloggerLogsResponse" fullword ascii
      $x2 = "get_Keylogger" fullword ascii
      $x3 = "HandleGetKeyloggerLogsResponse" fullword ascii

      $s1 = "DoShellExecuteResponse" fullword ascii
      $s2 = "GetPasswordsResponse" fullword ascii
      $s3 = "GetStartupItemsResponse" fullword ascii
      $s4 = "<GetGenReader>b__7" fullword ascii
      $s5 = "RunHidden" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and $x1 ) or ( all of them )
}

rule MAL_QuasarRAT_May19_1 {
   meta:
      description = "Detects QuasarRAT malware"
      author = "Florian Roth"
      reference = "https://blog.ensilo.com/uncovering-new-activity-by-apt10"
      date = "2019-05-27"
      hash1 = "0644e561225ab696a97ba9a77583dcaab4c26ef0379078c65f9ade684406eded"
   strings:
      $x1 = "Quasar.Common.Messages" ascii fullword
      $x2 = "Client.MimikatzTools" ascii fullword
      $x3 = "Resources.powerkatz_x86.dll" ascii fullword
      $x4 = "Uninstalling... good bye :-(" wide fullword

      $xc1 = { 41 00 64 00 6D 00 69 00 6E 00 00 11 73 00 63 00
               68 00 74 00 61 00 73 00 6B 00 73 00 00 1B 2F 00
               63 00 72 00 65 00 61 00 74 00 65 00 20 00 2F 00
               74 00 6E 00 20 00 22 00 00 27 22 00 20 00 2F 00
               73 }
      $xc2 = { 00 70 00 69 00 6E 00 67 00 20 00 2D 00 6E 00 20
               00 31 00 30 00 20 00 6C 00 6F 00 63 00 61 00 6C
               00 68 00 6F 00 73 00 74 00 20 00 3E 00 20 00 6E
               00 75 00 6C 00 0D 00 0A 00 64 00 65 00 6C 00 20
               00 2F 00 61 00 20 00 2F 00 71 00 20 00 2F 00 66
               00 20 00 }
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and 1 of them
}
