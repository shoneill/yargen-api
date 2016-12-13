/*
	Yara Rule Set
	Author: YarGen Rule Generator
	Date: 2016-10-21
	Identifier:
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_2ec15623_9757_11e6_960e_80e65024849a {
	meta:
		description = "Auto-generated rule - file 2ec15623-9757-11e6-960e-80e65024849a.file"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-10-21"
		hash1 = "fe5c1b0ec3a82aeb16d6290a0a550e1b773927077a16b382f6fdecaa183f0107"
	strings:
		$s1 = "FtpOoe" fullword ascii
		$s2 = "./0123456789:;<=>?@abcdefghijklm[*" fullword ascii
		$s3 = "PMM/dd/yG" fullword ascii
		$s4 = "fs /QW" fullword ascii
		$s5 = "HH:mm:)_" fullword ascii
		$s6 = "22 <D@22 #HDL2 #" fullword ascii
		$s7 = "2r @,\\2r #0p8r #" fullword ascii
		$s8 = "nopqrstuvwxyz[\\" fullword ascii
		$s9 = "Jsooxk" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 400KB and ( all of ($s*) ) ) or ( all of them )
}
