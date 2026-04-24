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
        $ips += $ipString
        return $ips
    }
    
    # Standard range generation (Network+1 to Broadcast-1)
    for ($i = ($network + 1); $i -lt $broadcast; $i++) {
        $nextBytes = [BitConverter]::GetBytes([uint32]$i)
        if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($nextBytes) }
        $ips += ([System.Net.IPAddress]$nextBytes).IPAddress
    }
    return $ips
}

$targets = @()
foreach ($s in $Subnets) { $targets += Expand-Subnet $s }

# perform parallel ping sweep using jobs
$jobs = @()
if ($targets.Count -gt 0) {
    foreach ($ip in $targets) {
        $jobs += Test-Connection -ComputerName $ip -Count 1 -AsJob
    }

    # wait for pings to finish
    Wait-Job $jobs -Timeout 15 | Out-Null
    $responds = Receive-Job $jobs | Where-Object { $_.Status -eq "Success" -or $_.ResponseTime -ne $null } | Select-Object -ExpandProperty Address
    Remove-Job $jobs -Force
}

# correlate responding ips with mac addresses
$results = @()
$neighbors = Get-NetNeighbor -AddressFamily IPv4
foreach ($ip in $responds) {
    if ($ip -notmatch '^\d') { continue }
    $n = $neighbors | Where-Object { $_.IPAddress -eq $ip }
    $results += [PSCustomObject]@{
        ip       = $ip
        mac      = if ($n) { $n.LinkLayerAddress } else { "Unknown" }
        hostname = "Active-Host"
        os       = "Unknown"
        vendor   = "Detected-Live"
    }
}

# convert to json for the python core
Write-Output ($results | ConvertTo-Json -Compress)
