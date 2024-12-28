# Get-NetNTLM
This is a port of Internal Monologue from https://github.com/GhostPack/Seatbelt 
Like Seatbelt, this code will utilize the local SSPI to elict NetNTLM and therefore little to no network traffic will be generated
The DisableESS option can be utilized and if you would like the attempt to disable session security in NetNTLMv1

Unlike Internal Monologue, this code will not attempt to impersonate a user or modify the registry keys to downgrade to NTLMv1
See the following for an example https://github.com/eladshamir/Internal-Monologue

# Compile 
```
make
```

# Usage
```
Get-NetNTLM <--DisableESS>
```