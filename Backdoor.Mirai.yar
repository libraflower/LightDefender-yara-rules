import "hash"
import "pe"

rule Backdoor_Mirai_1 {
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

rule Backdoor_Mirai_2 {
   meta:
      description = "Backdoor.Mirai"
      author = "LightDefender"
      date = "2021-07-21"
      hash1 = "19f11c9f85f5328d2fff11dc6fd51a1a9b5b1a813b179cf468941c78262640db"
      hash2 = "313d26bd272fad373e9b6c0efae6f04a48cced0b29a80b1ff49d5a78496b23ac"
      hash3 = "33798085c4daf6210db3646183c7f13b54e8aa30d3d31510143db01fcee845a6"
      hash4 = "7e37d4255a3af2864c15864a9e7ea745e8302e75c7c63eac88fe223cfd553405"
      hash5 = "cad92edc5ad54d479314e04abdb3490d2271f1b7b305de0215bcef655ed5b79f"
      hash6 = "e202a567d164d429fe0a32bf9edc91fab61ad78f5da090f5c688fdf39e50f324"
      hash7 = "fac3928ee12386a63f3f284376e89a7338bf987c4db4f1292aca61778f3c8d3b"
   strings:
      $s1 = "dakuexecbin" fullword ascii
      $s2 = "sefaexec" fullword ascii
      $s3 = "deexec" fullword ascii
      $s4 = "1337SoraLOADER" fullword ascii
      $s5 = "airdropmalware" fullword ascii
      $s6 = "trojan" fullword ascii
      $s7 = "GhostWuzHere666" fullword ascii
      $s8 = "wordminer" fullword ascii
      $s9 = "newnetword" fullword ascii
      $s10 = "netstats" fullword ascii
      $s11 = "plzjustfuckoff" fullword ascii
      $s12 = "131.153.18.72" fullword ascii
      $s13 = "198.199.78.243" fullword ascii
      $s14 = "scanspc" fullword ascii
      $s15 = "scanppc" fullword ascii
      $s16 = "scanmips" fullword ascii
      $s17 = "scanmpsl" fullword ascii
      $header = {7F 45 4C 46 01 01 01}
   condition:
      $header at 0 and 5 of them
}

rule Backdoor_Mirai_3 {
   meta:
      description = "Backdoor.Mirai"
      author = "LightDefender"
      date = "2021-07-31"
      hash1 = "16e14763992fbd91d2552149ea589fe6b5a1c26334e707e0e48995abe73e78df"
   strings:
      $s1 = "YourMicrowaveIsAPieceofShit" fullword ascii
      $header = {7F 45 4C 46 01 01 01}
   condition:
      $header at 0 and 2 of them
}

rule Backdoor_Mirai_4 {
   meta:
      description = "Backdoor.Mirai"
      author = "LightDefender"
      date = "2021-08-01"
      hash1 = "0a962f3e1e5c14a7a4ef08a00512030669beca5f5a143e955450d0beee212258"
      hash2 = "0e144ed6bd445e2bb7c15bd9b50e00a73f2135b93919cfff8e0b67b3600c2b26"
      hash3 = "55af9ed857a717106cd570794bb34d1e0b966b41dac86c87f384f508d88bf5a3"
      hash4 = "6a78ac289ec2d1acb5510cc7156634e3dc938115f6f3cb6fd035c4954f0593de"
      hash5 = "6d1c12f73c92036da4ab02d756db3f34f0fd58f341a9a1c245f314a5c27c58d2"
      hash6 = "ab2c9018c9cd5964dee5cd7775fcce5774e4d8f71e8a5d7a0b2c2a18f6af7aed"
      hash7 = "b6d0d8e89763f4df5dc86ab2edc7487a63c6a4659fdd61203ce9f99d00a31656"
      hash8 = "d218a3b902a3d7407f647b2ac27f0ee6117fda96fd8b368433882eb3c1c20390"
      hash9 = "e27849c2ad6d26a95b7d16ebc20286f1252ea7c8c676b12c7affc6f9afcd9c2a"
   strings:
      $s1 = "/bin/busybox PEACH" fullword ascii
      $s2 = "peachy botnet" fullword ascii
      $s3 = "applet not found" fullword ascii
      $s4 = "136.144.41.71" fullword ascii
      $s5 = ":/bin:/usr/bin" fullword ascii
      $header = {7F 45 4C 46 01 01 01}
   condition:
      $header at 0 and all of them
}

rule Mirai_Aug_3 {
   meta:
      description = "Backdoor.Mirai"
      author = "LightDefender"
      date = "2021-08-04"
      hash1 = "023e1861a8ed70114bf2de8b3fa9a1d1d1f17dc6a9a4b1a103a45ce6d0af6403"
      hash2 = "06e28121840dc393205119e8e070b055acf5c8903bd4f65338ea854f40bc287f"
      hash3 = "081d225ae39659e6d20b413ca7fd97e0894cda2b17afc12af36bbda3e0d84926"
      hash4 = "2b0586cc22d6f97b545675b3df6cafd7723cee0a8064992d3266055bfdd49fe6"
      hash5 = "33cd409dc7b32a9587e0d20e51a7a70da61245cb86adff3f799935896b551d55"
      hash6 = "67a4dff2d8f461ab987039f666695a52f9a60346ac867b8075c294474e16c002"
      hash7 = "7f57c7d3ee07b74c375ef861c83f2de445001701c3d8fb87c1b9c5350f3172f0"
      hash8 = "83a5f1b66ada31e0c3dc7f406d6f8a713481ac4cca262529cba38b6a6e684e8e"
      hash9 = "89a51f3d83e127c6b9ffcf862aa48292d8ec30b0b1a655f58065595755e2799e"
      hash10 = "94097ec769ef5e8bccb409d76682eae377380e473216de298511a6d6beef5fa7"
      hash11 = "9c720fe11463bc966611e955782d3a309490a933d7d26505b9229b4bf12c57ec"
      hash12 = "a0467702202ef43e0a6a6036a616f7aa744852b190d528e7fdc8e55d8ed0606d"
      hash13 = "a828ed22e636b655fa96ca8096010d32bfa729c282fef3afb1e3193302a2a1bf"
      hash14 = "abbdc3e208fca4b75ffa66ee81165737403cd9d850f10850230688fa9affa0bb"
      hash15 = "b47213623b3c07711fc2b405cf03dbb9f1c5162fad22ff0eee7144a962b2a332"
      hash16 = "b7d2fc7c2302f93fac1d21c2313b157707c32761832f17eb86f556459f894750"
      hash17 = "b8a798108c62312fe8d6b6a38134d08c5581d66a0540feb49928baadcd27201a"
      hash18 = "bd82aa484cd78fad40d790856ee56946a32700c17b0003bebbc6c896b9f9a98a"
      hash19 = "c21c3031870297ebfd81db6b25d992048861704abc4ab49954a3cf58ba941931"
      hash20 = "ca9b9fb575695e8542bdb63acd9c9c47de4fa3fa86466cbd6c0029db8ed897cf"
      hash21 = "cba3acaaf43bf09868e11dae733fd13c4cf8b9dd1de03e5aacea9badeff7ee86"
      hash22 = "ceda4455eef9ccc448e33f146bfb65fe936785f869935aee9e77e2e0e99eae9d"
      hash23 = "db1471220052aab0c4c60c12a8eccbd9e604292b27af34f9fd7b7130ab1ec7be"
   strings:
      $s1 = "xmhdipc" fullword ascii
      $s2 = "realtek" fullword ascii
      $s3 = "dreambox" fullword ascii
      $s4 = "juantech" fullword ascii
      $s5 = "/bin/busybox PEACH" fullword ascii
      $s6 = "peachy botnet" fullword ascii
      $s7 = "applet not found" fullword ascii
      $s8 = "meinsm" fullword ascii
      $s9 = "admin1234" fullword ascii
      $s10 = "administrator" fullword ascii
      $s11 = "Administrator" fullword ascii
      $s12 = "password" fullword ascii
      $s13 = "default" fullword ascii
      $s14 = "smcadmin" fullword ascii
      $s15 = "supervisor" fullword ascii
      $s16 = "7ujMko0vizxv" fullword ascii
      $s17 = "7ujMko0admin" fullword ascii
      $s18 = "Zte521" fullword ascii
      $s19 = "klv1234" fullword ascii
      $s20 = "admin1" fullword ascii
   condition:
      ( uint16(0) == 0x457f and ( 8 of them )
      ) or ( all of them )
}

rule Backdoor_Mirai_Aug_6 {
   meta:
      description = "Backdoor.Mirai"
      author = "LightDefender"
      date = "2021-08-07"
      hash1 = "a73af22662e16d8fb8c88830eb6470e7c010ffd42e1e67382cabf33f9644a5e8"
   strings:
      $s1 = "Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T HaxErS" fullword ascii
      $s2 = "/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A" ascii
      $s3 = "/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38" ascii
      $s4 = "/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93" ascii
      $s5 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ" ascii
      $s6 = "/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A" fullword ascii
      $s7 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ" ascii
      $s8 = "/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID" ascii
      $s9 = "37.0.11.137" fullword ascii
   condition:
      uint16(0) == 0x457f and
      6 of them
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
