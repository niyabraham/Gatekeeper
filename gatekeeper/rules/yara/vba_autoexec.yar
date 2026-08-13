/*
    vba_autoexec.yar
    Detects VBA auto-execution triggers — entry points that fire
    without any user interaction on document open or close.

    MITRE ATT&CK: T1137 (Office Application Startup)
                  T1059.005 (Visual Basic)
*/

rule VBA_AutoExec_Trigger
{
    meta:
        description = "Detects VBA auto-execution entry points (Auto_Open, Workbook_Open, etc.)"
        weight      = 30
        category    = "autoexec"
        mitre       = "T1137"

    strings:
        $auto_open      = "Auto_Open"      nocase
        $autoopen       = "AutoOpen"       nocase
        $document_open  = "Document_Open"  nocase
        $workbook_open  = "Workbook_Open"  nocase
        $autoexec       = "AutoExec"       nocase
        $autoclose      = "Auto_Close"     nocase
        $document_close = "Document_Close" nocase
        $app_startup    = "App_Startup"    nocase
        $workbook_close = "Workbook_BeforeClose" nocase

    condition:
        any of them
}

rule VBA_AutoExec_Combined_With_Shell
{
    meta:
        description = "Auto-execution entry point combined with shell activity — high confidence malicious"
        weight      = 70
        category    = "autoexec_shell"
        mitre       = "T1059.005"

    strings:
        $auto1  = "Auto_Open"      nocase
        $auto2  = "Workbook_Open"  nocase
        $auto3  = "Document_Open"  nocase
        $auto4  = "AutoOpen"       nocase
        $shell1 = "Shell("         nocase
        $shell2 = "WScript.Shell"  nocase
        $shell3 = "CreateObject"   nocase
        $shell4 = "ShellExecute"   nocase

    condition:
        any of ($auto*) and any of ($shell*)
}

rule VBA_AutoExec_Combined_With_Network
{
    meta:
        description = "Auto-execution combined with network access — dropper pattern"
        weight      = 80
        category    = "autoexec_network"
        mitre       = "T1105"

    strings:
        $auto1 = "Auto_Open"     nocase
        $auto2 = "Workbook_Open" nocase
        $auto3 = "Document_Open" nocase
        $auto4 = "AutoOpen"      nocase
        $net1  = "MSXML2.XMLHTTP"       nocase
        $net2  = "WinHttp"              nocase
        $net3  = "URLDownloadToFile"    nocase
        $net4  = "Net.WebClient"        nocase
        $net5  = "DownloadString"       nocase
        $net6  = "DownloadFile"         nocase

    condition:
        any of ($auto*) and any of ($net*)
}
