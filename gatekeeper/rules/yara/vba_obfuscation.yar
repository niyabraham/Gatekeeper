/*
    vba_obfuscation.yar
    Detects obfuscation techniques used to evade static analysis in VBA macros.

    MITRE ATT&CK: T1027 (Obfuscated Files or Information)
                  T1140 (Deobfuscate/Decode Files or Information)
*/

rule VBA_Chr_Obfuscation_Moderate
{
    meta:
        description = "Moderate Chr() usage — possible obfuscation of individual keywords"
        weight      = 25
        category    = "obfuscation"
        mitre       = "T1027"

    strings:
        $chr1 = "Chr("  nocase
        $chr2 = "ChrW(" nocase
        $chr3 = "Chr$(" nocase

    condition:
        #chr1 + #chr2 + #chr3 >= 3 and #chr1 + #chr2 + #chr3 < 10
}

rule VBA_Chr_Obfuscation_Heavy
{
    meta:
        description = "Heavy Chr() encoding — deliberate obfuscation of strings from static analysis"
        weight      = 50
        category    = "obfuscation"
        mitre       = "T1027"

    strings:
        $chr1 = "Chr("  nocase
        $chr2 = "ChrW(" nocase
        $chr3 = "Chr$(" nocase

    condition:
        #chr1 + #chr2 + #chr3 >= 10
}

rule VBA_Base64_Decode_Routine
{
    meta:
        description = "Detects Base64 decoding patterns used to hide payloads inside macro code"
        weight      = 50
        category    = "obfuscation"
        mitre       = "T1027"

    strings:
        $b64_1 = "FromBase64String" nocase
        $b64_2 = "ToBase64String"   nocase
        $b64_3 = "MSXML2.DOMDocument" nocase
        $b64_4 = "base64"           nocase
        $b64_5 = "decodestring"     nocase
        $b64_6 = "Convert.FromBase" nocase

    condition:
        any of them
}

rule VBA_StrReverse_Obfuscation
{
    meta:
        description = "Detects StrReverse() used to store keywords backwards and evade matching"
        weight      = 40
        category    = "obfuscation"
        mitre       = "T1027"

    strings:
        $sr1 = "StrReverse(" nocase
        $sr2 = "StrReverse " nocase

    condition:
        any of them
}

rule VBA_Split_Join_Obfuscation
{
    meta:
        description = "Detects Split/Join array obfuscation used to fragment detection strings"
        weight      = 30
        category    = "obfuscation"
        mitre       = "T1027"

    strings:
        $sj1 = "Split("  nocase
        $sj2 = "Join("   nocase
        $sj3 = "Replace(" nocase

    condition:
        all of them
}

rule VBA_Hex_String_Construction
{
    meta:
        description = "Detects hex string construction used to assemble payloads at runtime"
        weight      = 35
        category    = "obfuscation"
        mitre       = "T1027"

    strings:
        $hex1 = "&H"
        $hex2 = "CByte(" nocase
        $hex3 = "CInt("  nocase

    condition:
        #hex1 > 8 and any of ($hex2, $hex3)
}

rule VBA_Late_Binding_Obfuscation
{
    meta:
        description = "Detects late binding via CallByName to hide API calls from static analysis"
        weight      = 45
        category    = "obfuscation"
        mitre       = "T1027"

    strings:
        $cb1 = "CallByName(" nocase
        $cb2 = "CallByName " nocase

    condition:
        any of them
}
