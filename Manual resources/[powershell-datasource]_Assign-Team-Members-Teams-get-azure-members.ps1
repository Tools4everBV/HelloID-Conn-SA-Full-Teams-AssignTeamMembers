#Input: TeamsAdminUser
#Input: TeamsAdminPWD

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# variables configured in form
$groupId = $datasource.selectedgroup.GroupId
$role = $datasource.role

$connected = $false
try {
	$module = Import-Module MicrosoftTeams
	$pwd = ConvertTo-SecureString -string $TeamsAdminPWD -AsPlainText -Force
	$cred = New-Object System.Management.Automation.PSCredential $TeamsAdminUser, $pwd
	$teamsConnection = Connect-MicrosoftTeams -Credential $cred
    Write-Information "Connected to Microsoft Teams"
    $connected = $true
}
catch
{	
    Write-Error "Could not connect to Microsoft Teams. Error: $($_.Exception.Message)"
}

if ($connected)
{
	try {
		$users = Get-TeamUser -GroupId $groupId -Role $role
        Write-Information "Result count: $(@($users).Count)"

		if(@($users).Count -gt 0){
			foreach($user in $users)
			{
				$resultObject = @{User=$user.User; UserId=$user.UserId; Name=$user.Name; Role=$user.Role}
                Write-Output $resultObject
			}
		}
	}
	catch
	{
		Write-Error "Error searching Azure. Error: $($_.Exception.Message)"
    }
}
