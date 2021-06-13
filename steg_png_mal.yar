  
import "pe"

rule steg_mal_png {

	meta:
		author = "Thatskriptkid"
		date = "2021-05-27"
		description = "Malicious png files in .NET malware often have the same gAMA, pHYs values and first two bytes of IDAT"

	strings:
	
		$gAMA_chunk = {0000000467414d410000b18f0bfc6105}
		$pHYs_chunk = {000000097048597300000ec300000ec301}
		$IDAT_chunk = {0000ffb249444154785e}

	condition:
		uint16(0) == 0x5a4d
		
		and pe.imports("mscoree.dll")

		and $gAMA_chunk

		and $pHYs_chunk

		and $IDAT_chunk 
}
