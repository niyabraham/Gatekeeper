/*
    vba_download_cradles.yar
    Detects HTTP/FTP download cradles used to fetch second-stage payloads.

    MITRE ATT&CK: T1105 (Ingress Tool Transfer)
                  T1071.001 (Web Protocols)
*/

rule VBA_HTTP_Download_Cradle
{
    meta:
        description = "Detects XMLHTTP or WinHTTP used to download remote payloads"
        weight      = 60
        category    = "download"
        mitre       = "T1105"

    strings:
        $xml1  = "MSXML2.XMLHTTP"         nocase
        $xml2  = "MSXML2.ServerXMLHTTP"   nocase
        $xml3  = "Microsoft.XMLHTTP"      nocase
        $win1  = "WinHttp.WinHttpRequest" nocase
        $win2  = "WinHTTP"                nocase
        $open  = ".Open"                  nocase
        $send  = ".Send"                  nocase
        $resp  = ".ResponseBody"          nocase
        $resp2 = ".ResponseText"          nocase

    condition:
        any of ($xml*, $win*) and any of ($open, $send, $resp, $resp2)
}

rule VBA_URLDownloadToFile
{
    meta:
        description = "Detects URLDownloadToFile / URLDownloadToCacheFile API calls"
        weight      = 60
        category    = "download"
        mitre       = "T1105"

    strings:
        $url1 = "URLDownloadToFile"       nocase
        $url2 = "URLDownloadToCacheFile"  nocase
        $url3 = "urlmon"                  nocase

    condition:
        any of them
}

rule VBA_WebClient_Download
{
    meta:
        description = "Detects .NET WebClient used for payload download (PowerShell-in-macro pattern)"
        weight      = 60
        category    = "download"
        mitre       = "T1105"

    strings:
        $wc1 = "Net.WebClient"     nocase
        $wc2 = "DownloadString("   nocase
        $wc3 = "DownloadFile("     nocase
        $wc4 = "DownloadData("     nocase
        $wc5 = "OpenRead("         nocase

    condition:
        $wc1 or (any of ($wc2, $wc3, $wc4, $wc5))
}

rule VBA_Download_And_Execute
{
    meta:
        description = "Download cradle combined with execution — high confidence dropper"
        weight      = 90
        category    = "dropper"
        mitre       = "T1105"

    strings:
        $dl1 = "URLDownloadToFile"    nocase
        $dl2 = "MSXML2.XMLHTTP"       nocase
        $dl3 = "WinHttp"              nocase
        $dl4 = "Net.WebClient"        nocase
        $dl5 = "DownloadFile"         nocase
        $dl6 = "DownloadString"       nocase
        $dl7 = "ADODB.Stream"         nocase
        $ex1 = "Shell("               nocase
        $ex2 = "WScript.Shell"        nocase
        $ex3 = "ShellExecute"         nocase
        $ex4 = "powershell"           nocase
        $ex5 = "cmd.exe"              nocase
        $ex6 = ".Run("                nocase

    condition:
        any of ($dl*) and any of ($ex*)
}

rule VBA_Hardcoded_URL
{
    meta:
        description = "Detects hardcoded HTTP/HTTPS/FTP URLs in macro code"
        weight      = 40
        category    = "network_ioc"
        mitre       = "T1071.001"

    strings:
        $http  = "http://"  nocase
        $https = "https://" nocase
        $ftp   = "ftp://"   nocase

    condition:
        any of them
}

rule VBA_BITS_Transfer
{
    meta:
        description = "Detects Background Intelligent Transfer Service (BITS) abuse for stealthy download"
        weight      = 55
        category    = "download"
        mitre       = "T1197"

    strings:
        $bits1 = "BITSAdmin"                  nocase
        $bits2 = "BITS.BackgroundCopyManager"  nocase
        $bits3 = "BackgroundCopy"              nocase
        $bits4 = "IBackgroundCopyManager"      nocase

    condition:
        any of them
}

rule VBA_ADODB_Stream_Write
{
    meta:
        description = "Detects ADODB.Stream used to write downloaded payloads to disk"
        weight      = 55
        category    = "download"
        mitre       = "T1105"

    strings:
        $adodb = "ADODB.Stream"  nocase
        $write = ".Write("       nocase
        $save  = ".SaveToFile("  nocase
        $open  = ".Open"         nocase
        $type  = ".Type"         nocase

    condition:
        $adodb and 2 of ($write, $save, $open, $type)
}
