$errorPrefix = "ERROR: "
$prefix = "Service '{0}' "
$ERROR_SERVICE_REQUEST_TIMEOUT = $errorPrefix + $prefix + "request timeout"
$ERROR_SERVICE_ALREADY_RUNNING = $prefix + "already running."
$ERROR_SERVICE_ALREADY_STOPPED = $prefix + "already stopped."
$ERROR_SERVICE_DOES_NOT_EXIST = $errorPrefix + $prefix + "does not exist."

function Invoke-ShaiyaService {
    Param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet('ps_userLog', 'ps_session', 'ps_gameLog', 'ps_dbAgent', 'ps_game', 'ps_login')]
        [string] $name,
        [Parameter(Mandatory = $true)]
        [ServiceProcess.ServiceControllerStatus] $status
    )
    $service = (Get-Service -DisplayName "Shaiya *") | Where-Object Name -ieq $name
    if ( -not $service ) {
        $Host.UI.WriteErrorLine($ERROR_SERVICE_DOES_NOT_EXIST -f $name)
        Break
    }
    if ( $service.Status -eq $status ) {
        if ( [ServiceProcess.ServiceControllerStatus]::Running -eq $status ) {
            $Host.UI.WriteWarningLine($ERROR_SERVICE_ALREADY_RUNNING -f $name)
        }
        elseif ( [ServiceProcess.ServiceControllerStatus]::Stopped -eq $status ) {
            $Host.UI.WriteWarningLine($ERROR_SERVICE_ALREADY_STOPPED -f $name)
        }
        return
    }
    try {
        if ( [ServiceProcess.ServiceControllerStatus]::Running -eq $status ) {
            $service.Start()
            $service.WaitForStatus($status, (New-Object Timespan 0, 0, 5))
        }
        elseif ( [ServiceProcess.ServiceControllerStatus]::Stopped -eq $status ) {
            $service.Stop()
            $service.WaitForStatus($status, (New-Object Timespan 0, 0, 20))
        }
    }
    catch [Management.Automation.MethodInvocationException], [ServiceProcess.TimeoutException] {
        $errorText = $ERROR_SERVICE_REQUEST_TIMEOUT -f $name
        $errorText += " while waiting on status '"
        if ( [ServiceProcess.ServiceControllerStatus]::Running -eq $status ) {
            $errorText += "Running'"
        }
        elseif ( [ServiceProcess.ServiceControllerStatus]::Stopped -eq $status ) {
            $errorText += "Stopped'"
        }
        $Host.UI.WriteErrorLine($errorText)
        Break
    }
}

function Invoke-ShaiyaServices {
    Param
    (
        [Parameter(Mandatory = $true)]
        [ServiceProcess.ServiceControllerStatus] $status
    )
    $names = @('ps_userLog', 'ps_session', 'ps_gameLog', 'ps_dbAgent', 'ps_game', 'ps_login')
    if ( [ServiceProcess.ServiceControllerStatus]::Stopped -eq $status ) {
        [array]::Reverse($names)
    }
    foreach ($name in $names) {
        Invoke-ShaiyaService -name $name -status $status
    }
}

function Test-ShaiyaServerAgents {
    $agents = (Get-Service -DisplayName "Shaiya Agent *")
    try {
        foreach ($agent in $agents) {
            $agent.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running, '00:00:08')
        }
    }
    catch [Management.Automation.MethodInvocationException], [ServiceProcess.TimeoutException] {
        $Host.UI.WriteErrorLine($ERROR_SERVICE_REQUEST_TIMEOUT -f $agent.Name)
        Break
    }
}

function Start-ShaiyaServer {
    Test-ShaiyaServerAgents
    $status = [ServiceProcess.ServiceControllerStatus]::Running
    Invoke-ShaiyaServices $status
}

function Stop-ShaiyaServer {
    Test-ShaiyaServerAgents
    $status = [ServiceProcess.ServiceControllerStatus]::Stopped
    Invoke-ShaiyaServices $status
}

function Start-ShaiyaService {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string] $name
    )
    Test-ShaiyaServerAgents
    $status = [ServiceProcess.ServiceControllerStatus]::Running
    Invoke-ShaiyaService -name $name -status $status
}

function Stop-ShaiyaService {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string] $name
    )
    Test-ShaiyaServerAgents
    $status = [ServiceProcess.ServiceControllerStatus]::Stopped
    Invoke-ShaiyaService -name $name -status $status
}

function Install-PSM_ServiceMgr {
    if ($PSCommandPath -eq $null) { 
        function GetPSCommandPath() { 
            return $MyInvocation.PSCommandPath;
        }
        $PSCommandPath = GetPSCommandPath;
    }
    $destination = "$env:SYSTEMDRIVE\Shaiya\Services\PSM_ServiceMgr.ps1"

    Write-Host "Installing script in [$destination] ..."
    New-Item -ItemType File -Path $destination -Force | Out-Null
    Copy-Item $PSCommandPath -Destination $destination -Force -Recurse
    Write-Host ""

    $startupTrigger = New-ScheduledTaskTrigger -AtStartup
    $user = "NT AUTHORITY\SYSTEM"
    $taskAction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -NoLogo -NonInteractive -ExecutionPolicy Bypass -File $destination Start-Server"
    Write-Host "Installing task for system startup ..."
    Register-ScheduledTask -TaskName "Start Shaiya Server" -Trigger $startupTrigger -User $user -Action $taskAction -RunLevel Highest –Force | Out-Null
    Write-Host ""

    Write-Host "Installing task for system shutdown ..."
    $key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Shutdown\0"
    New-Item -Path $key -Force | Out-Null
    New-ItemProperty -Path $key -Name GPO-ID -Value LocalGPO -Force | Out-Null
    New-ItemProperty -Path $key -Name SOM-ID -Value Local -Force | Out-Null
    New-ItemProperty -Path $key -Name FileSysPath -Value "$env:SystemRoot\System32\GroupPolicy\Machine" -Force | Out-Null
    New-ItemProperty -Path $key -Name DisplayName -Value "Local Group Policy" -Force | Out-Null
    New-ItemProperty -Path $key -Name GPOName -Value "Local Group Policy" -Force | Out-Null
    New-ItemProperty -Path $key -Name PSScriptOrder -Value 3 -PropertyType "DWord" -Force | Out-Null

    $key = "$key\0"
    New-Item -Path $key -Force | Out-Null
    New-ItemProperty -Path $key -Name "Script" -Value $destination -Force | Out-Null
    New-ItemProperty -Path $key -Name "Parameters" -Value "Stop-Server" -Force | Out-Null
    New-ItemProperty -Path $key -Name "IsPowershell" -Value 1 -PropertyType "DWord" -Force | Out-Null
    New-ItemProperty -Path $key -Name "ExecTime" -Value 0 -PropertyType "QWord" -Force | Out-Null
    Write-Host ""

    Write-Host "Installing functions as shortcut ..."
    Import-Module $destination -Force
}