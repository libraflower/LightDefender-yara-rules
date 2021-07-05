import "hash"
import "pe"


rule Backdoor_Mirai {
   meta:
      description = "Backdoor.Mirai"
      author = "LightDefender"
      date = "2021-07-01"
   strings:
      $s1 = "your_verry_fucking_gay" fullword ascii
      $s2 = "airdropmalware" fullword ascii
      $s3 = "TheWeeknd" fullword ascii
      $header = {7F 45 4C 46 01 01 01}
   condition:
      $header at 0 and 3 of them
}

rule Mirai_Generic_Arch : MALW
{
	meta:
		description = "Mirai Botnet TR-069 Worm - Generic Architecture" 
		author = "Felipe Molina / @felmoltor"
		date = "2016-12-04"
		version = "1.0" 
		ref1 = "http://www.theregister.co.uk/2016/11/28/router_flaw_exploited_in_massive_attack/"	
		ref2 = "https://isc.sans.edu/forums/diary/Port+7547+SOAP+Remote+Code+Execution+Attack+Against+DSL+Modems/21759" 
		ref3 = "https://krebsonsecurity.com/2016/11/new-mirai-worm-knocks-900k-germans-offline/"

	strings:
		$miname = "Myname--is:"
		$iptables1 = "busybox iptables -A INPUT -p tcp --destination-port 7547 -j DROP"
		$iptables2 = "busybox iptables -A INPUT -p tcp --destination-port 5555 -j DROP"
		$procnet = "/proc/net/tcp"

	condition:
		$miname and $iptables1 and $iptables2 and $procnet
}

rule Mirai_MIPS_LSB : MALW
{
	meta:
		description = "Mirai Botnet TR-069 Worm - MIPS LSB" 
		author = "Felipe Molina / @felmoltor"
		date = "2016-12-04"
		version = "1.0" 
		MD5 = "bf650d39eb603d92973052ca80a4fdda"
		SHA1 = "03ecd3b49aa19589599c64e4e7a51206a592b4ef"
		ref1 = "http://www.theregister.co.uk/2016/11/28/router_flaw_exploited_in_massive_attack/"	
		ref2 = "https://isc.sans.edu/forums/diary/Port+7547+SOAP+Remote+Code+Execution+Attack+Against+DSL+Modems/21759" 
		ref3 = "https://krebsonsecurity.com/2016/11/new-mirai-worm-knocks-900k-germans-offline/"

	strings:
		$miname = "Myname--is:"
		$iptables1 = "busybox iptables -A INPUT -p tcp --destination-port 7547 -j DROP"
		$iptables2 = "busybox iptables -A INPUT -p tcp --destination-port 5555 -j DROP"
		$procnet = "/proc/net/tcp"

	condition:
		$miname and $iptables1 and $iptables2 and $procnet and
		hash.sha1(0,filesize) == "03ecd3b49aa19589599c64e4e7a51206a592b4ef"
}
rule Mirai_MIPS_MSB : MALW
{
	meta:
		description = "Mirai Botnet TR-069 Worm - MIPS MSB" 
		author = "Felipe Molina / @felmoltor"
		date = "2016-12-04"
		version = "1.0" 
		MD5 = "0eb51d584712485300ad8e8126773941"	
		SHA1 = "18bce2f0107b5fab1b0b7c453e2a6b6505200cbd"
		ref1 = "http://www.theregister.co.uk/2016/11/28/router_flaw_exploited_in_massive_attack/"	
		ref2 = "https://isc.sans.edu/forums/diary/Port+7547+SOAP+Remote+Code+Execution+Attack+Against+DSL+Modems/21759" 
		ref3 = "https://krebsonsecurity.com/2016/11/new-mirai-worm-knocks-900k-germans-offline/"

	strings:
		$miname = "Myname--is:"
		$iptables1 = "busybox iptables -A INPUT -p tcp --destination-port 7547 -j DROP"
		$iptables2 = "busybox iptables -A INPUT -p tcp --destination-port 5555 -j DROP"
		$procnet = "/proc/net/tcp"

	condition:
		$miname and $iptables1 and $iptables2 and $procnet and 
		hash.sha1(0,filesize) == "18bce2f0107b5fab1b0b7c453e2a6b6505200cbd"
}

rule Mirai_ARM_LSB : MALW
{
	meta:
		description = "Mirai Botnet TR-069 Worm - ARM LSB" 
		author = "Felipe Molina / @felmoltor"
		date = "2016-12-04"
		version = "1.0" 
		MD5= "eba670256b816e2d11f107f629d08494"
		SHA1 = "8a25dee4ea7d61692b2b95bd047269543aaf0c81"
		ref1 = "http://www.theregister.co.uk/2016/11/28/router_flaw_exploited_in_massive_attack/"	
		ref2 = "https://isc.sans.edu/forums/diary/Port+7547+SOAP+Remote+Code+Execution+Attack+Against+DSL+Modems/21759" 
		ref3 = "https://krebsonsecurity.com/2016/11/new-mirai-worm-knocks-900k-germans-offline/"

	strings:
		$miname = "Myname--is:"
		$iptables1 = "busybox iptables -A INPUT -p tcp --destination-port 7547 -j DROP"
		$iptables2 = "busybox iptables -A INPUT -p tcp --destination-port 5555 -j DROP"
		$procnet = "/proc/net/tcp"

	condition:
		$miname and $iptables1 and $iptables2 and $procnet and 
		hash.sha1(0,filesize) == "8a25dee4ea7d61692b2b95bd047269543aaf0c81"
}

rule Mirai_Renesas_SH : MALW
{
	meta:
		description = "Mirai Botnet TR-069 Worm - Renesas SH LSB" 
		author = "Felipe Molina / @felmoltor"
		date = "2016-12-04"
		version = "1.0" 
		MD5 = "863dcf82883c885b0686dce747dcf502"
		SHA1 = "bdc86295fad70480f0c6edcc37981e3cf11d838c"
		ref1 = "http://www.theregister.co.uk/2016/11/28/router_flaw_exploited_in_massive_attack/"	
		ref2 = "https://isc.sans.edu/forums/diary/Port+7547+SOAP+Remote+Code+Execution+Attack+Against+DSL+Modems/21759" 
		ref3 = "https://krebsonsecurity.com/2016/11/new-mirai-worm-knocks-900k-germans-offline/"

	strings:
		$miname = "Myname--is:"
		$iptables1 = "busybox iptables -A INPUT -p tcp --destination-port 7547 -j DROP"
		$iptables2 = "busybox iptables -A INPUT -p tcp --destination-port 5555 -j DROP"
		$procnet = "/proc/net/tcp"

	condition:
		$miname and $iptables1 and $iptables2 and $procnet and 
		hash.sha1(0,filesize) == "bdc86295fad70480f0c6edcc37981e3cf11d838c"
}
rule Mirai_PPC_Cisco : MALW
{
	meta:
		description = "Mirai Botnet TR-069 Worm - PowerPC or Cisco 4500" 
		author = "Felipe Molina / @felmoltor"
		date = "2016-12-04"
		version = "1.0" 
		MD5= "dbd92b08cbff8455ff76c453ff704dc6"
		SHA1 = "6933d555a008a07b859a55cddb704441915adf68"
		ref1 = "http://www.theregister.co.uk/2016/11/28/router_flaw_exploited_in_massive_attack/"	
		ref2 = "https://isc.sans.edu/forums/diary/Port+7547+SOAP+Remote+Code+Execution+Attack+Against+DSL+Modems/21759" 
		ref3 = "https://krebsonsecurity.com/2016/11/new-mirai-worm-knocks-900k-germans-offline/"

	strings:
		$miname = "Myname--is:"
		$iptables1 = "busybox iptables -A INPUT -p tcp --destination-port 7547 -j DROP"
		$iptables2 = "busybox iptables -A INPUT -p tcp --destination-port 5555 -j DROP"
		$procnet = "/proc/net/tcp"

	condition:
		( $miname and $iptables1 and $iptables2 and $procnet ) and 
		hash.sha1(0,filesize) == "6933d555a008a07b859a55cddb704441915adf68"
}

rule Mirai_SPARC_MSB : MALW
{
	meta:
		description = "Mirai Botnet TR-069 Worm - SPARC MSB" 
		author = "Felipe Molina / @felmoltor"
		date = "2016-12-04"
		version = "1.0" 
		MD5= "05891dbabc42a36f33c30535f0931555"
		SHA1 = "3d770480b6410cba39e19b3a2ff3bec774cabe47"
		ref1 = "http://www.theregister.co.uk/2016/11/28/router_flaw_exploited_in_massive_attack/"	
		ref2 = "https://isc.sans.edu/forums/diary/Port+7547+SOAP+Remote+Code+Execution+Attack+Against+DSL+Modems/21759" 
		ref3 = "https://krebsonsecurity.com/2016/11/new-mirai-worm-knocks-900k-germans-offline/"

	strings:
		$miname = "Myname--is:"
		$iptables1 = "busybox iptables -A INPUT -p tcp --destination-port 7547 -j DROP"
		$iptables2 = "busybox iptables -A INPUT -p tcp --destination-port 5555 -j DROP"
		$procnet = "/proc/net/tcp"

	condition:
		( $miname and $iptables1 and $iptables2 and $procnet ) and 
		hash.sha1(0,filesize) == "3d770480b6410cba39e19b3a2ff3bec774cabe47"
}


rule Mirai_1 : MALW
{
	meta:
		description = "Mirai Variant 1"
		author = "Joan Soriano / @joanbtl"
		date = "2017-04-16"
		version = "1.0"
		MD5 = "655c3cf460489a7d032c37cd5b84a3a8"
		SHA1 = "4dd3803956bc31c8c7c504734bddec47a1b57d58"

	strings:
		$dir1 = "/dev/watchdog"
		$dir2 = "/dev/misc/watchdog"
		$pass1 = "PMMV"
		$pass2 = "FGDCWNV"
		$pass3 = "OMVJGP"
	condition:
		$dir1 and $pass1 and $pass2 and not $pass3 and not $dir2

}
rule Mirai_2 : MALW
{
meta:
	description = "Mirai Variant 2"
	author = "Joan Soriano / @joanbtl"
	date = "2017-04-16"
	version = "1.0"
	MD5 = "0e5bda9d39b03ce79ab8d421b90c0067"
	SHA1 = "96f42a9fad2923281d21eca7ecdd3161d2b61655"

    strings:
	$dir1 = "/dev/watchdog"
	$dir2 = "/dev/misc/watchdog"
        $s1 = "PMMV"
        $s2 = "ZOJFKRA"
        $s3 = "FGDCWNV"
        $s4 = "OMVJGP"
    condition:
        $dir1 and $dir2 and $s1 and $s2 and $s3 and not $s4 

}

rule Mirai_3 : MALW
{
    meta:
	description = "Mirai Variant 3"
	author = "Joan Soriano / @joanbtl"
	date = "2017-04-16"
	version = "1.0"
	MD5 = "bb22b1c921ad8fa358d985ff1e51a5b8"
	SHA1 = "432ef83c7692e304c621924bc961d95c4aea0c00"

    strings:
            $dir1 = "/dev/watchdog"
            $dir2 = "/dev/misc/watchdog"
            $s1 = "PMMV"
            $s2 = "ZOJFKRA"
            $s3 = "FGDCWNV"
            $s4 = "OMVJGP"
	    $ssl = "ssl3_ctrl"
    condition:
            $dir1 and $dir2 and $s1 and $s2 and $s3 and $s4 and not $ssl

}

rule Mirai_4 : MALW
{
	meta:
		description = "Mirai Variant 4"
		author = "Joan Soriano / @joanbtl"
		date = "2017-04-16"
		version = "1.0"
		MD5 = "f832ef7a4fcd252463adddfa14db43fb"
		SHA1 = "4455d237aadaf28aafce57097144beac92e55110"
	strings:
		$s1 = "210765"
		$s2 = "qllw"
		$s3 = ";;;;;;"
	condition:
		$s1 and $s2 and $s3
}

rule Mirai_Dwnl : MALW
{
	meta:
		description = "Mirai Downloader"
		author = "Joan Soriano / @joanbtl"
		date = "2017-04-16"
		version = "1.0"
		MD5 = "85784b54dee0b7c16c57e3a3a01db7e6"
		SHA1 = "6f6c625ef730beefbc23c7f362af329426607dee"
	strings:
		$s1 = "GET /mirai/"
		$s2 = "dvrHelper"
	condition:
		$s1 and $s2
}

rule Mirai_5 : MALW
{
	meta:
		description = "Mirai Variant 5"
		author = "Joan Soriano / @joanbtl"
		date = "2017-04-16"
		version = "1.0"
		MD5 = "7e17c34cddcaeb6755c457b99a8dfe32"
		SHA1 = "b63271672d6a044704836d542d92b98e2316ad24"

	strings:
		    $dir1 = "/dev/watchdog"
		    $dir2 = "/dev/misc/watchdog"
		    $s1 = "PMMV"
		    $s2 = "ZOJFKRA"
		    $s3 = "FGDCWNV"
		    $s4 = "OMVJGP"
		    $ssl = "ssl3_ctrl"
	condition:
		    $dir1 and $dir2 and $s1 and $s2 and $s3 and $s4 and $ssl

}
rule elf_mirai_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-06-10"
        version = "1"
        description = "Detects elf.mirai."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/elf.mirai"
        malpedia_rule_date = "20210604"
        malpedia_hash = "be09d5d71e77373c0f538068be31a2ad4c69cfbd"
        malpedia_version = "20210616"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    /* DISCLAIMER
     * The strings used in this rule have been automatically selected from the
     * disassembly of memory dumps and unpacked files, using YARA-Signator.
     * The code and documentation is published here:
     * https://github.com/fxb-cocacoding/yara-signator
     * As Malpedia is used as data source, please note that for a given
     * number of families, only single samples are documented.
     * This likely impacts the degree of generalization these rules will offer.
     * Take the described generation method also into consideration when you
     * apply the rules in your use cases and assign them confidence levels.
     */


    strings:
        $sequence_0 = { 8b1408 895310 8b54080c 66895314 }
            // n = 4, score = 300
            //   8b1408               | mov                 dl, al
            //   895310               | sub                 esp, 0x54
            //   8b54080c             | xor                 eax, eax
            //   66895314             | mov                 ebx, dword ptr [esp + 0x74]

        $sequence_1 = { e9???????? e8???????? 66894314 e9???????? }
            // n = 4, score = 300
            //   e9????????           |                     
            //   e8????????           |                     
            //   66894314             | dec                 eax
            //   e9????????           |                     

        $sequence_2 = { 89d0 c1e005 01d0 89ca 29c2 }
            // n = 5, score = 300
            //   89d0                 | add                 esp, 0x10
            //   c1e005               | inc                 eax
            //   01d0                 | je                  0x91d
            //   89ca                 | sub                 esp, 0xc
            //   29c2                 | push                0xc

        $sequence_3 = { 8d429f 3c19 7705 8d42e0 }
            // n = 4, score = 300
            //   8d429f               | push                0
            //   3c19                 | push                0xb
            //   7705                 | push                edi
            //   8d42e0               | mov                 dword ptr [esp + 0x2c], eax

        $sequence_4 = { 66894304 7406 66c743064000 c643092f }
            // n = 4, score = 300
            //   66894304             | mov                 eax, dword ptr [esp + 0x30]
            //   7406                 | dec                 eax
            //   66c743064000         | mov                 dword ptr [ebx + 0x30], eax
            //   c643092f             | dec                 ecx

        $sequence_5 = { 894330 c6433801 c6433903 c6433a03 }
            // n = 4, score = 300
            //   894330               | xor                 eax, eax
            //   c6433801             | dec                 eax
            //   c6433903             | mov                 ecx, dword ptr [esp + 0x10]
            //   c6433a03             | jle                 0x223

        $sequence_6 = { c7433400000000 894330 c6433801 c6433903 }
            // n = 4, score = 300
            //   c7433400000000       | lea                 edx, dword ptr [edx + edx*4]
            //   894330               | add                 edx, edx
            //   c6433801             | mov                 edx, dword ptr [esp + 0x18]
            //   c6433903             | mov                 dword ptr [esp + 0x54], 0

        $sequence_7 = { c1e005 01d0 89ca 29c2 }
            // n = 4, score = 300
            //   c1e005               | mov                 edi, esp
            //   01d0                 | mov                 dword ptr [esp + 0x14], eax
            //   89ca                 | dec                 esp
            //   29c2                 | mov                 esi, dword ptr [ebp - 0x10]

        $sequence_8 = { e8???????? c7433400000000 894330 c6433801 c6433903 }
            // n = 5, score = 300
            //   e8????????           |                     
            //   c7433400000000       | mov                 ebx, dword ptr [esp + 0x68]
            //   894330               | mov                 ecx, 4
            //   c6433801             | mov                 ecx, 4
            //   c6433903             | mov                 ecx, 5

        $sequence_9 = { 807c242b00 66894304 7406 66c743064000 }
            // n = 4, score = 300
            //   807c242b00           | inc                 cx
            //   66894304             | mov                 dword ptr [esp + 4], eax
            //   7406                 | jle                 0x13b
            //   66c743064000         | mov                 esi, 8

    condition:
        7 of them and filesize < 131728
}
// From ClamAV
rule Win_Trojan_Mirai_5840677_0
{
    strings:
			$a0 = { 6563686f202d6e6520272573272025732075706e703b202f62696e2f62757379626f782045434348490d0a }

    condition:
        any of them
}
