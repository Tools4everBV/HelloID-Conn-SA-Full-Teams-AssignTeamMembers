#Input: TeamsAdminUser
#Input: TeamsAdminPWD

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

$connected = $false
try {
	$module = Import-Module AzureAD
	$pwd = ConvertTo-SecureString -string $TeamsAdminPWD -AsPlainText -Force
	$cred = New-Object System.Management.Automation.PSCredential $TeamsAdminUser, $pwd
	$teamsConnection = Connect-AzureAD -Credential $cred
    Write-Information "Connected to Azure AD"
    $connected = $true
}
catch
{	
    Write-Error "Could not connect to Azure AD. Error: $($_.Exception.Message)"
}

if ($connected)
{
	try {
		$users = Get-AzureADUser -All:$true | Sort-Object name
        Write-Information "Result count: $(@($users).Count)"

		if(@($users).Count -gt 0){
			foreach($user in $users)
			{
				$resultObject = @{User=$user.UserPrincipalName; Name=$user.displayName;}
				Write-Output $resultObject
			}
		}
	}
	catch
	{
		Write-Error "Error searching Azure. Error: $($_.Exception.Message)"
    }
}
