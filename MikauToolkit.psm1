function Start-SD
{
	A:\sd.exe
}

function New-SDPrompt
{
	A:\sd_prompt\New-SDPrompt.ps1 -Generate
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

Export-ModuleMember -Function * -Alias *