/*
    vba_persistence.yar
    Detects persistence mechanisms accessed from VBA macros.

    MITRE ATT&CK: T1547.001 (Registry Run Keys / Startup Folder)
                  T1053.005 (Scheduled Task)
                  T1137.001 (Office Template Macros)
                  T1137.006 (Add-ins)
*/

rule VBA_Registry_Run_Key_Persistence
{
    meta:
        description = "Detects registry Run/RunOnce key modification for persistence"
        weight      = 60
        category    = "persistence"
        mitre       = "T1547.001"

    strings:
        $reg1  = "RegWrite"            nocase
        $reg2  = "RegRead"             nocase
        $hkcu1 = "HKEY_CURRENT_USER"  nocase
        $hkcu2 = "HKCU"               nocase
        $hklm1 = "HKEY_LOCAL_MACHINE"  nocase
        $hklm2 = "HKLM"               nocase
        $run1  = "\\Run\\"             nocase
        $run2  = "\\RunOnce\\"         nocase
        $run3  = "\\RunOnceEx\\"       nocase
        $run4  = "CurrentVersion\\Run" nocase

    condition:
        any of ($reg*) and any of ($hkcu*, $hklm*) and any of ($run*)
}

rule VBA_Registry_Write_General
{
    meta:
        description = "Detects any registry write from a VBA macro — lower confidence persistence signal"
        weight      = 30
        category    = "persistence"
        mitre       = "T1547.001"

    strings:
        $reg1  = "RegWrite"            nocase
        $hkcu1 = "HKEY_CURRENT_USER"  nocase
        $hkcu2 = "HKCU"               nocase
        $hklm1 = "HKEY_LOCAL_MACHINE"  nocase
        $hklm2 = "HKLM"               nocase

    condition:
        $reg1 and any of ($hkcu*, $hklm*)
}

rule VBA_Startup_Folder_Write
{
    meta:
        description = "Detects writes to Windows startup folder for persistence"
        weight      = 55
        category    = "persistence"
        mitre       = "T1547.001"

    strings:
        $sf1 = "Startup"                              nocase
        $sf2 = "StartupFolder"                        nocase
        $sf3 = "Start Menu\\Programs\\Startup"        nocase
        $sf4 = "AppData\\Roaming\\Microsoft\\Windows\\Start Menu" nocase
        $sf5 = "ProgramData\\Microsoft\\Windows\\Start Menu"      nocase

    condition:
        any of them
}

rule VBA_Scheduled_Task_Creation
{
    meta:
        description = "Detects scheduled task creation from VBA for deferred or recurring execution"
        weight      = 60
        category    = "persistence"
        mitre       = "T1053.005"

    strings:
        $st1 = "schtasks"         nocase
        $st2 = "Schedule.Service" nocase
        $st3 = "ITaskService"     nocase
        $st4 = "RegisterTask"     nocase
        $st5 = "/create"          nocase
        $st6 = "TaskScheduler"    nocase

    condition:
        any of them
}

rule VBA_Office_Addin_Persistence
{
    meta:
        description = "Detects Office add-in or template abuse for macro persistence across documents"
        weight      = 50
        category    = "persistence"
        mitre       = "T1137.006"

    strings:
        $xla1  = ".xlam"               nocase
        $xla2  = ".xla"                nocase
        $dot1  = "Normal.dotm"         nocase
        $dot2  = "PERSONAL.XLSB"       nocase
        $addin = "AddIns"              nocase
        $auto1 = "Application.Addins"  nocase

    condition:
        any of them
}
