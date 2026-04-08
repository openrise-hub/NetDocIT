# NetDocIT SNMP Poller - Andrick: Paste your logic here
# output must be a json array of objects

# todo: implement SNMP polling (feature 6.3)
$results = @()

# placeholder for appliance details
# $results += [PSCustomObject]@{
#     ip     = "192.168.1.1"
#     sysDescr = "Cisco IOS Software..."
#     sysName  = "Core-RT-01"
# }

# convert to json for the python core
Write-Output ($results | ConvertTo-Json -Compress)
