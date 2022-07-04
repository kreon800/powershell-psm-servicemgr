# powershell-psm-servicemgr
Script to automate some startup/shutdown routines

# Usage
1. Download PSM_ServiceMgr.ps1 .
2. Open PowerShell Console located in the directory where this downloaded file was saved (e.g. ``Downloads``).
3. Type in 
```ps
PS ...\Downloads> . .\PSM_ServiceMgr.ps1 ; Install-PSM_ServiceMgr
```
4. Enjoy starting/stopping the Shaiya server automatically as a service.

# Requirements
The [Shaiya services](#allowed-service-names) need to be installed on the system already.

# Features
### The whole server complex
- `Start-ShaiyaServer`
- `Stop-ShaiyaServer`

### Just specific service
- `Start-ShaiyaService <name>`
- `Stop-ShaiyaService <name>`

#### Allowed service names
- ps_session
- ps_userLog
- ps_login
- ps_game
- ps_dbAgent
- ps_gameLog

# Examples
```ps
Stop-ShaiyaService ps_game
...
Start-ShaiyaService ps_game
```
