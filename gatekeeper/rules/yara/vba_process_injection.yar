/*
    vba_process_injection.yar
    Detects Windows API calls associated with process injection and
    memory manipulation from VBA macros.

    MITRE ATT&CK: T1055 (Process Injection)
                  T1055.001 (Dynamic-link Library Injection)
                  T1055.003 (Thread Execution Hijacking)
*/

rule VBA_Process_Injection_APIs
{
    meta:
        description = "Detects Windows process injection API declarations in VBA (requires 2+ APIs)"
        weight      = 80
        category    = "injection"
        mitre       = "T1055"

    strings:
        $va   = "VirtualAlloc"         nocase
        $vax  = "VirtualAllocEx"       nocase
        $wpm  = "WriteProcessMemory"   nocase
        $rpm  = "ReadProcessMemory"    nocase
        $ct   = "CreateThread"         nocase
        $crt  = "CreateRemoteThread"   nocase
        $crtx = "CreateRemoteThreadEx" nocase
        $op   = "OpenProcess"          nocase
        $ot   = "OpenThread"           nocase
        $vp   = "VirtualProtect"       nocase
        $vpx  = "VirtualProtectEx"     nocase
        $sus  = "SuspendThread"        nocase
        $res  = "ResumeThread"         nocase
        $ctx  = "GetThreadContext"     nocase
        $sctx = "SetThreadContext"     nocase

    condition:
        2 of them
}

rule VBA_NT_API_Injection
{
    meta:
        description = "Detects low-level NT API calls used for injection to bypass security monitoring"
        weight      = 85
        category    = "injection"
        mitre       = "T1055"

    strings:
        $nt1 = "NtAllocateVirtualMemory"  nocase
        $nt2 = "NtWriteVirtualMemory"     nocase
        $nt3 = "NtCreateThreadEx"         nocase
        $nt4 = "NtQueueApcThread"         nocase
        $nt5 = "NtUnmapViewOfSection"     nocase
        $nt6 = "ZwAllocateVirtualMemory"  nocase
        $nt7 = "ZwWriteVirtualMemory"     nocase

    condition:
        any of them
}

rule VBA_DLL_Injection_Declare
{
    meta:
        description = "Detects DLL function imports via Declare statement targeting injection-related DLLs"
        weight      = 70
        category    = "injection"
        mitre       = "T1055.001"

    strings:
        $decl1 = "Declare Function" nocase
        $decl2 = "Declare Sub"      nocase
        $decl3 = "Declare PtrSafe"  nocase
        $dll1  = "kernel32"         nocase
        $dll2  = "ntdll"            nocase
        $dll3  = "user32"           nocase
        $dll4  = "advapi32"         nocase
        $dll5  = "msvcrt"           nocase

    condition:
        any of ($decl*) and any of ($dll*)
}

rule VBA_LoadLibrary_GetProcAddress
{
    meta:
        description = "Detects dynamic DLL loading pattern — resolves APIs at runtime to avoid import scanning"
        weight      = 65
        category    = "injection"
        mitre       = "T1055.001"

    strings:
        $ll  = "LoadLibrary("    nocase
        $ll2 = "LoadLibraryA("   nocase
        $ll3 = "LoadLibraryW("   nocase
        $gpa = "GetProcAddress(" nocase

    condition:
        any of ($ll*) and $gpa
}

rule VBA_Shellcode_Indicators
{
    meta:
        description = "Detects shellcode staging patterns — byte array allocation and memory execution"
        weight      = 75
        category    = "injection"
        mitre       = "T1055"

    strings:
        $byte_arr = "Dim"          nocase
        $byte_t   = "Byte"         nocase
        $val      = "VirtualAlloc" nocase
        $rtlmv    = "RtlMoveMemory" nocase
        $copymem  = "CopyMemory"   nocase

    condition:
        ($byte_arr and $byte_t) and ($val or $rtlmv or $copymem)
}
