rule Jupyter
{
meta:
	description = "Identifies Jupyter aka SolarMarker, backdoor."
	author = "@bartblaze"
	date = "2021-06"
	tlp = "White"

strings:
	$ = "var __addr__=" ascii wide
	$ = "var __hwid__=" ascii wide
	$ = "var __xkey__=" ascii wide
	$ = "solarmarker.dat" ascii wide

condition:
	3 of them
}

/*
 This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/
rule Jupyter_Infostealer_DLL
{
   meta:
        author = "Lucas Acha (http://www.lukeacha.com)"
        description = "observed powershell command strings"
        reference = "http://security5magics.blogspot.com/2020/12/tracking-jupyter-malware.html" 
  strings:
      $a = /\[.\..\]::run\(\)/ nocase
      $b = /\[.\..\]::run\(\)/ nocase wide
  condition:
      any of them
}

rule Jupyter_Dropped_File
{
   meta:
        author = "Lucas Acha (http://www.lukeacha.com)"
        description = "observed wide strings with malicious DLL loaded by Jupyer malware"
        reference = "http://security5magics.blogspot.com/2020/12/tracking-jupyter-malware.html" 
  strings:
      $a = "solarmarker.dat" nocase wide
  condition:
      all of them
}

rule Suspicious_PS_Strings
{
   meta:
        author = "Lucas Acha (http://www.lukeacha.com)"
        description = "observed set of strings which are likely malicious, observed with Jupyter malware. "
        reference = "http://security5magics.blogspot.com/2020/12/tracking-jupyter-malware.html" 
    strings:
        $a = "windowstyle=7" nocase
        $b = "[system.io.file]:" nocase
        $c = ":readallbytes" nocase
        $d = "system.text.encoding]::" nocase
        $e = "utf8.getstring" nocase
        $f = "([system.convert]::" nocase
        $g = "frombase64string" nocase
        $h = "[system.reflection.assembly]::load" nocase
        $i = "-bxor" nocase
    condition:
        6 of them
}
