function Start-SD
{
	A:\sd.exe
}

function New-SDPrompt
{
	Set-Location -Path A:\sd_prompt\New-ImageGeneration
	python.exe .\New-ImageGeneration.py
}

function Set-DiscordSDPresenceMessage{
	python.exe A:\SD_presence.py
}

function Start-O4GPT{
	&'C:\Program Files\O4GPT\O4GPT.service.exe'
	Start-Sleep -Seconds 15
	&'C:\Program Files\O4GPT\O4GPT-Personnel.exe'
}

function Set-TeamsPresenceMessage{
param(
	[Parameter]
	[string]
	$Message,
	[Parameter]
	[string]
	$NumberofDays
	)
	C:\Users\fxbeaulieu\Documents\git-repo\Set-TeamsPresenceMessage\Set-PresenceMessage.ps1 -PresenceMessage $Message -Expiration $NumberOfDays
}

function Invoke-ValidatedElevatedExec
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Global:ExecuteThisFileAsAdmin
    )

    function Start-Exec
    {
        & $Global:ExecuteThisFileAsAdmin
    }

    function Find-ExecPath
    {
        if (Test-Path $Global:ExecuteThisFileAsAdmin)
        {
            Start-Exec
        }
    }
    function Get-TerminalSessionElevationState
    {
        $CurrentUserIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $CurrentSecurityPrincipal = New-Object System.Security.Principal.WindowsPrincipal($CurrentUserIdentity)
        $IsAdmin = $CurrentSecurityPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
        if (! $IsAdmin)
        {
            Write-Host -ForegroundColor Yellow "La session PowerShell n'est pas exécutée en tant qu'administrateur. Vous devrez approuver le UAC pour l'élever avant que le script puisse s'exécuter."
            Start-Process 'powershell.exe' -WorkingDirectory "$PSScriptRoot" -ArgumentList "$PSCommandPath" -Verb RunAs
            Return
        }
        Find-ExecPath
    }

    Get-TerminalSessionElevationState
}

function Start-SSHKeysImport {
    param(
    #Fournir la paire d'infos requises avec le user distant en premier et le IP du serveur en deuxieme
    [Parameter(Mandatory)]
    [array[]]
    $SSHConnections
    )

	$CurrentConnectionUser = $ConnectionInfos[0]
	$CurrentConnectionServer = $ConnectionInfos[1]
	$CurrentConnection = ("$CurrentConnectionUser"+"@"+"$CurrentConnectionServer")
	try {
		Write-Output $KeysToImport | ssh $CurrentConnection "cat >> .ssh/authorized_keys"
	}
	catch {
		Write-Host -ForegroundColor Red "Erreur dans l'import de la clef"
	}
}

function Get-CredentialObject{
	param(
	[parameter(Mandatory)]
	[string]
	$UserNetuser,
	[parameter(Mandatory)]
	[string]
	$UserNetPass
	)
	$SecureNetPass = ConvertTo-SecureString -String $UserNetPass -AsPlainText -Force
	$UserNetLogin = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $UserNetUser,$SecureNetPass
	Return $UserNetLogin
}

function Invoke-MSIExtractFromEXE{
	param(
		[Parameter(Mandatory)]
		[string]
		$EXEFullPath,
		[Parameter(Mandatory)]
		[string]
		$OutputPath
	)
	&"$EXEFullPath" /s /x /b"$OutputPath" /v/qn
}

function Install-O4GPTCurrentDevBuild {
	D:\test_env\Install-O4GPTCurrentDevBuild.ps1
}

function Start-O4GPTDevBuild {
	&"C:\Users\fxbeaulieu\Documents\Homemade Tools\o4gpt_core\Start-O4GPT.ps1"
}

function Install-MikauToolkit {
	$MikauToolkit = "D:\git-repo\MikauToolkit"
	$PowerShellModulesPaths = @(
		"C:\Users\fxbeaulieu\Documents\PowerShell\Modules\",
		"C:\Program Files\PowerShell\7\Modules\",
		"C:\Users\fxbeaulieu\Documents\WindowsPowerShell\Modules\",
		"C:\Program Files (x86)\WindowsPowerShell\Modules\",
		"C:\Program Files\WindowsPowerShell\Modules\"
	)

	Foreach($ModulePath in $PowerShellModulesPaths)
	{
		Copy-Item -Path $MikauToolkit -Destination $ModulePath -Recurse -Force
	}
}

Export-ModuleMember -Function * -Alias *