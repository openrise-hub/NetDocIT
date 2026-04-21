param(
    [string[]]$Subnets
)

function Expand-Subnet($cidr) {
    if ($cidr -notmatch '(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,2})') { return @() }
    $ip = [ipaddress]$Matches[1]
    $mask = [int]$Matches[2]
    
    $ipBytes = $ip.GetAddressBytes()
    [Array]::Reverse($ipBytes)
    $ipInt = [BitConverter]::ToUInt32($ipBytes, 0)
    
    $hostCount = [math]::Pow(2, (32 - $mask))
    $ips = @()
    for ($i = 1; $i -lt ($hostCount - 1); $i++) {
        $nextIpInt = $ipInt + $i
        $nextIpBytes = [BitConverter]::GetBytes($nextIpInt)
        [Array]::Reverse($nextIpBytes)
        $ips += ([ipaddress]$nextIpBytes).IPAddress
    }
    return $ips
}

$targets = @()
foreach ($s in $Subnets) { $targets += Expand-Subnet $s }

# perform parallel ping sweep using jobs
$jobs = @()
foreach ($ip in $targets) {
    $jobs += Test-Connection -ComputerName $ip -Count 1 -AsJob
}

# wait for pings to finish
Wait-Job $jobs -Timeout 10 | Out-Null
$responds = Receive-Job $jobs | Where-Object { $_.ResponseTime -ne $null } | Select-Object -ExpandProperty Address

# correlate responding ips with mac addresses
$results = @()
$neighbors = Get-NetNeighbor -AddressFamily IPv4
foreach ($ip in $responds) {
    $n = $neighbors | Where-Object { $_.IPAddress -eq $ip }
    $results += [PSCustomObject]@{
        ip       = $ip
        mac      = if ($n) { $n.LinkLayerAddress } else { "Unknown" }
        hostname = "Active-Host"
        os       = "Unknown"
        vendor   = "Detected-Live"
    }
}

# clean up jobs
Remove-Job $jobs -Force

# convert to json for the python core
Write-Output ($results | ConvertTo-Json -Compress)
