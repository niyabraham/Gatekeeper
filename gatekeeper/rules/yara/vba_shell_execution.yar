/*
    vba_shell_execution.yar
    Detects shell command execution, COM object abuse, and PowerShell
    invocation from VBA macros.

    MITRE ATT&CK: T1059.001 (PowerShell)
                  T1059.005 (Visual Basic)
                  T1559.001 (Component Object Model)
*/

rule VBA_Shell_Function_Call
{
    meta:
        description = "Detects direct use of VBA Shell() function to execute external programs"
        weight      = 40
        category    = "execution"
        mitre       = "T1059.005"

    strings:
        $shell1 = "Shell("        nocase
        $shell2 = "Shell "        nocase
        $shell3 = "ShellExecute"  nocase
        $shell4 = "ShellExecuteA" nocase
        $shell5 = "ShellExecuteW" nocase

    condition:
        any of them
}

rule VBA_PowerShell_Invocation
{
    meta:
        description = "Detects PowerShell invocation from VBA — requires 2+ indicators to reduce FP"
        weight      = 60
        category    = "execution"
        mitre       = "T1059.001"

    strings:
        $ps1  = "powershell"        nocase
        $ps2  = "Invoke-Expression" nocase
        $ps3  = "IEX("              nocase
        $ps4  = "Invoke-Command"    nocase
        $ps5  = "EncodedCommand"    nocase
        $ps6  = " -enc "            nocase
        $ps7  = " -nop "            nocase
        $ps8  = "ExecutionPolicy"   nocase
        $ps9  = "bypass"            nocase
        $ps10 = "-WindowStyle"      nocase
        $ps11 = "hidden"            nocase

    condition:
        2 of them
}

rule VBA_CMD_Execution
{
    meta:
        description = "Detects cmd.exe invocation via VBA macros"
        weight      = 40
        category    = "execution"
        mitre       = "T1059.003"

    strings:
        $cmd1 = "cmd.exe"     nocase
        $cmd2 = "cmd /c"      nocase
        $cmd3 = "cmd /k"      nocase
        $cmd4 = "cmd /r"      nocase
        $cmd5 = "command.com" nocase
        $cmd6 = "/c start"    nocase

    condition:
        any of them
}

rule VBA_WScript_Shell_Abuse
{
    meta:
        description = "Detects WScript.Shell COM object creation and Run/Exec method calls"
        weight      = 50
        category    = "execution"
        mitre       = "T1059.005"

    strings:
        $wsh1 = "WScript.Shell"   nocase
        $wsh2 = "WScript.Network" nocase
        $run1 = ".Run("           nocase
        $run2 = ".Exec("          nocase
        $run3 = ".RunAs("         nocase

    condition:
        ($wsh1 or $wsh2) and any of ($run*)
}

rule VBA_Dangerous_COM_Object
{
    meta:
        description = "Detects CreateObject/GetObject with high-risk COM classes"
        weight      = 50
        category    = "execution"
        mitre       = "T1559.001"

    strings:
        $co1    = "CreateObject" nocase
        $co2    = "GetObject"    nocase
        $class1 = "WScript.Shell"                    nocase
        $class2 = "Scripting.FileSystemObject"       nocase
        $class3 = "Shell.Application"                nocase
        $class4 = "ADODB.Stream"                     nocase
        $class5 = "MSXML2.XMLHTTP"                   nocase
        $class6 = "MSXML2.ServerXMLHTTP"             nocase
        $class7 = "Microsoft.XMLHTTP"                nocase
        $class8 = "InternetExplorer.Application"     nocase
        $class9 = "Scripting.Dictionary"             nocase

    condition:
        any of ($co*) and any of ($class*)
}

rule VBA_Environ_Probing
{
    meta:
        description = "Detects environment variable probing used for evasion or payload staging"
        weight      = 25
        category    = "evasion"
        mitre       = "T1082"

    strings:
        $env1 = "Environ("     nocase
        $env2 = "APPDATA"      nocase
        $env3 = "USERPROFILE"  nocase
        $env4 = "COMSPEC"      nocase
        $env5 = "WINDIR"       nocase
        $env6 = "SystemRoot"   nocase
        $env7 = "ProgramFiles" nocase
        $env8 = "TEMP"         nocase

    condition:
        $env1 and 2 of ($env2, $env3, $env4, $env5, $env6, $env7, $env8)
}
