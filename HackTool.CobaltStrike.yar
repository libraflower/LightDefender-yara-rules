import "math"
import "pe"

private rule cobaltstrike_template_exe
{
    meta:
        description = "Template to provide executable detection Cobalt Strike payloads"
        reference = "https://www.cobaltstrike.com"
        author = "@javutin, @joseselvi"
    strings:
        $compiler = "mingw-w64 runtime failure" nocase

        $f1 = "VirtualQuery"   fullword
        $f2 = "VirtualProtect" fullword
        $f3 = "vfprintf"       fullword
        $f4 = "Sleep"          fullword
        $f5 = "GetTickCount"   fullword

        $c1 = { // Compare case insensitive with "msvcrt", char by char
                0f b6 50 01 80 fa 53 74 05 80 fa 73 75 42 0f b6
                50 02 80 fa 56 74 05 80 fa 76 75 34 0f b6 50 03
                80 fa 43 74 05 80 fa 63 75 26 0f b6 50 04 80 fa
                52 74 05 80 fa 72 75 18 0f b6 50 05 80 fa 54 74
        }
    condition:
        uint16(0) == 0x5a4d and
        filesize < 1000KB and
        $compiler and
        all of ($f*) and
        all of ($c*)
}   

private rule cobaltstrike_beacon_raw
{
    strings:
        $s1 = "%d is an x64 process (can't inject x86 content)" fullword
        $s2 = "Failed to impersonate logged on user %d (%u)" fullword
        $s3 = "powershell -nop -exec bypass -EncodedCommand \"%s\"" fullword
        $s4 = "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/'); %s" fullword
        $s5 = "could not run command (w/ token) because of its length of %d bytes!" fullword
        $s6 = "could not write to process memory: %d" fullword
        $s7 = "%s.4%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" fullword
        $s8 = "Could not connect to pipe (%s): %d" fullword

        $b1 = "beacon.dll"     fullword
        $b2 = "beacon.x86.dll" fullword
        $b3 = "beacon.x64.dll" fullword

    condition:
        uint16(0) == 0x5a4d and
        filesize < 1000KB and
        (
            any of ($b*) or
            5 of ($s*)
        )
}

private rule cobaltstrike_beacon_exe
{
    condition:
        cobaltstrike_template_exe and
        filesize > 100KB and filesize < 500KB and
        pe.sections[pe.section_index(".data")].raw_data_size > 200000 and
        math.entropy(pe.sections[pe.section_index(".data")].raw_data_offset + 1024, 150000 ) >= 7 
}

private rule cobaltstrike_beacon_b64
{
    strings:
        $s1a = "JWQgaXMgYW4geDY0IHByb2Nlc3MgKGNhbid0IGluam"
        $s1b = "ZCBpcyBhbiB4NjQgcHJvY2VzcyAoY2FuJ3QgaW5qZW"
        $s1c = "IGlzIGFuIHg2NCBwcm9jZXNzIChjYW4ndCBpbmplY3"

        $s2a = "RmFpbGVkIHRvIGltcGVyc29uYXRlIGxvZ2dlZCBvbi"
        $s2b = "YWlsZWQgdG8gaW1wZXJzb25hdGUgbG9nZ2VkIG9uIH"
        $s2c = "aWxlZCB0byBpbXBlcnNvbmF0ZSBsb2dnZWQgb24gdX"

        $s3a = "cG93ZXJzaGVsbCAtbm9wIC1leGVjIGJ5cGFzcyAtRW"
        $s3b = "b3dlcnNoZWxsIC1ub3AgLWV4ZWMgYnlwYXNzIC1Fbm"
        $s3c = "d2Vyc2hlbGwgLW5vcCAtZXhlYyBieXBhc3MgLUVuY2"

        $s4a = "SUVYIChOZXctT2JqZWN0IE5ldC5XZWJjbGllbnQpLk"
        $s4b = "RVggKE5ldy1PYmplY3QgTmV0LldlYmNsaWVudCkuRG"
        $s4c = "WCAoTmV3LU9iamVjdCBOZXQuV2ViY2xpZW50KS5Eb3"

    condition:
        filesize < 1000KB and
        5 of ($s*)
}

rule hacktool_windows_cobaltstrike_beacon
{
    meta:
        description = "Detection of the Beacon payload from Cobalt Strike"
        reference = "https://www.cobaltstrike.com/help-beacon"
        author = "@javutin, @joseselvi"
    condition:
        cobaltstrike_beacon_b64 or
        cobaltstrike_beacon_raw or
        cobaltstrike_beacon_exe
}

rule hacktool_windows_cobaltstrike_powershell
{
    meta:
        description = "Detection of the PowerShell payloads from Cobalt Strike"
        reference = "https://www.cobaltstrike.com/help-payload-generator"
        author = "@javutin, @joseselvi"
    strings:
        $ps1 = "Set-StrictMode -Version 2"
        $ps2 = "func_get_proc_address"
        $ps3 = "func_get_delegate_type"
        $ps4 = "FromBase64String"
        $ps5 = "VirtualAlloc"
        $ps6 = "var_code"
        $ps7 = "var_buffer"
        $ps8 = "var_hthread"

    condition:
        $ps1 at 0 and
        filesize < 1000KB and
        all of ($ps*)
}

rule hacktool_windows_cobaltstrike_powershell_2
{
    meta:
        description = "Detection of the PowerShell payloads from Cobalt Strike"
        author = "LightDefender"
        date = "2021-06-25"
    strings:
        $ps1 = "'System.dll'" ascii
        $ps2 = "Set-StrictMode -Version 2" ascii
        $ps3 = "GetProcAddress" ascii
        $ps4 = "start-job" ascii
        $ps5 = "VirtualAlloc" ascii

    condition:
        $ps2 at 0 and
        filesize < 1000KB and
        all of ($ps*)
}
