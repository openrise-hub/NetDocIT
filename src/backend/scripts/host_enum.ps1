param(
    [string[]]$IPs
)

# host enumerator
$results = @()

foreach ($ip in $IPs) {
    try {
        # gather os and system info via cim
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $ip -ErrorAction Stop -OperationTimeoutSec 5
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ComputerName $ip -ErrorAction Stop -OperationTimeoutSec 5
        
        $obj = New-Object PSObject -Property @{
            ip       = $ip
            hostname = $os.CSName
            os       = $os.Caption
            build    = $os.Version
            vendor   = $cs.Manufacturer
        }
        $results += $obj
    } catch {
        continue
    }
}

# return json output
Write-Output ($results | ConvertTo-Json -Compress)
