# NetDocIT: Native Environment Discovery
# Returns JSON of interfaces and routes

$interfaces = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notmatch 'Loopback' } | ForEach-Object {
    $iface = Get-NetIPInterface -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4
    $adapter = Get-NetAdapter -InterfaceIndex $_.InterfaceIndex
    
    [PSCustomObject]@{
        name        = $_.InterfaceAlias
        description = $adapter.Status
        ipv4        = $_.IPAddress
        mac         = $adapter.MacAddress
    }
}

$routes = Get-NetRoute -AddressFamily IPv4 | ForEach-Object {
    # Convert PrefixLength to dotted-decimal Netmask
    $mask = if ($_.DestinationPrefix.Contains("/")) {
        $prefix = [int]$_.DestinationPrefix.Split('/')[1]
        $binMask = ([String]('1' * $prefix)).PadRight(32, '0')
        $octets = for ($i = 0; $i -lt 32; $i += 8) { [Convert]::ToByte($binMask.Substring($i, 8), 2) }
        $octets -join '.'
    } else { "255.255.255.255" }

    [PSCustomObject]@{
        network    = $_.DestinationPrefix.Split('/')[0]
        netmask    = $mask
        prefix_len = if ($_.DestinationPrefix.Contains("/")) { $_.DestinationPrefix.Split('/')[1] } else { "32" }
        gateway    = $_.NextHop
        interface  = $_.InterfaceAlias
        local_addr = (Get-NetIPAddress -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4 | Select-Object -First 1).IPAddress
    }
}

$output = @{
    interfaces = $interfaces
    routes     = $routes
}

$output | ConvertTo-Json
