param(
    [string[]]$Subnets
)

function Expand-Subnet($cidr) {
    if ($cidr -notmatch '(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,2})') { return @() }
    $ipString = $Matches[1]
    $prefix = [int]$Matches[2]
    
    # 32-bit integer conversion
    $ip = [System.Net.IPAddress]::Parse($ipString)
    $ipBytes = $ip.GetAddressBytes()
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($ipBytes) }
    $ipUint = [BitConverter]::ToUInt32($ipBytes, 0)
    
    # Calculate mask and boundaries
    # Using [int64] to prevent signed overflow during bitwise shifts
    $mask = [uint32]([int64]0xFFFFFFFF -shl (32 - $prefix))
    if ($prefix -eq 0) { $mask = 0 }
    
    $network = $ipUint -band $mask
    $broadcast = $network -bor (-bnot $mask)
    
    $ips = @()
    # Point-to-point behavior for /31 and /32
    if ($prefix -ge 31) {
        for ($i = ($network + 1); $i -le ($broadcast - 1); $i++) {
            $nextBytes = [BitConverter]::GetBytes([uint32]$i)
            if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($nextBytes) }
            $ips += ([System.Net.IPAddress]$nextBytes).IPAddress
        }
        return $ips
    }

    $targets = @()
    foreach ($s in $Subnets) { $targets += Expand-Subnet $s }

    $responds = @()
    if ($targets.Count -gt 0) {
        $taskList = New-Object System.Collections.Generic.List[System.Threading.Tasks.Task[System.Net.NetworkInformation.PingReply]]
        foreach ($ip in $targets) {
            $p = New-Object System.Net.NetworkInformation.Ping
            $taskList.Add($p.SendPingAsync($ip, 1000))
        }

        [System.Threading.Tasks.Task]::WaitAll($taskList.ToArray())

        for ($i = 0; $i -lt $taskList.Count; $i++) {
            if ($taskList[$i].Status -eq 'RanToCompletion' -and $taskList[$i].Result.Status -eq 'Success') {
                $responds += $targets[$i]
            }
        }
    }

    $results = @()
    $neighbors = Get-NetNeighbor -AddressFamily IPv4
    $arpTable = arp -a | Out-String

    foreach ($ip in $responds) {
        # try get-netneighbor
        $n = $neighbors | Where-Object { $_.IPAddress -eq $ip } | Select-Object -First 1
        $mac = "Unknown"
        if ($n) { 
            $mac = $n.LinkLayerAddress 
        } 
        elseif ($arpTable -match "$ip\s+([0-9a-fA-F-]{17})") {
            # fallback to arp -a parsing
            $mac = $Matches[1]
        }
    
        $results += [PSCustomObject]@{
            ip     = [string]$ip
            mac    = [string]$mac
            os     = "Unknown"
            vendor = "Detected-Live"
        }
    }

    # convert to json for the python core
    Write-Output ($results | ConvertTo-Json -Compress)
