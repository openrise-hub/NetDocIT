# NetDocIT Active Scanner - Andrick: Paste your logic here
# output must be a json array of objects

# todo: implement ping sweep logic (feature 6.1)
$results = @()

# placeholder for discovered devices
# $results += [PSCustomObject]@{
#     ip       = "192.168.1.10"
#     mac      = "AA:BB:CC:DD:EE:FF"
#     hostname = "Discovered-Device"
#     os       = "Unknown"
#     vendor   = "Detected-Vendor"
# }

# convert to json for the python core
Write-Output ($results | ConvertTo-Json -Compress)
