#Input: TeamsAdminUser
#Input: TeamsAdminPWD

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# variables configured in form
$groupId = $form.teams.GroupId
$MembersToAdd = $form.members.leftToRight
$MembersToRemove = $form.members.rightToLeft
$OwnersToAdd = $form.owners.leftToRight
$OwnersToRemove = $form.Owners.rightToLeft

$connected = $false
try {
	$module = Import-Module MicrosoftTeams -Verbose:$false
	$pwd = ConvertTo-SecureString -string $TeamsAdminPWD -AsPlainText -Force
	$cred = New-Object System.Management.Automation.PSCredential $TeamsAdminUser, $pwd
	$teamsConnection = Connect-MicrosoftTeams -Credential $cred -Verbose:$false
    Write-Information "Connected to Microsoft Teams"
    $connected = $true
}
catch
{	
    Write-Error "Could not connect to Microsoft Teams. Error: $($_.Exception.Message)"
}

if ($connected)
{
	if($MembersToAdd -ne $null){
		Write-Warning "Starting to add Users to Team Members of [$groupId]: $($MembersToAdd | Out-String)"
		
		foreach($memberToAdd in $MembersToAdd)
		{
			try{
				$addMember = Add-TeamUser -GroupId $groupId -User $memberToAdd.User -Role 'Member'
				Write-Information "Successfully added User [$($memberToAdd.User)] to Team Members of [$groupId]"
			}
			catch{
				Write-Error "Could not add User [$($memberToAdd.User)] to Team Members of [$groupId]. Error: $($_.Exception.Message)"
            }
		}
	}
	
	if($MembersToRemove -ne $null){
		Write-Warning "Starting to remove Users to Team Members of [$groupId]: $($MembersToRemove | Out-String)"
		$usersToRemoveJson =  $MembersToRemove | ConvertFrom-Json
			
		foreach($memberToRemove in $MembersToRemove)
		{
			try{
				$removeMember = Remove-TeamUser -GroupId $groupId -User $memberToRemove.User
                Write-Information "Successfully removed User [$($memberToRemove.User)] from Team Members of [$groupId]"
			}
			catch{
				Wirte-Error "Could not remove User [$($memberToRemove.User)] from Team Members of [$groupId]. Error: $($_.Exception.Message)"
            }
		}   
	}
	
	if($OwnersToAdd -ne $null){
		Write-Warning "Starting to add Users to Team Owners of [$groupId]: $($OwnersToAdd | Out-String)"
		
		foreach($ownerToAdd in $OwnersToAdd)
		{
			try{
				$addOwner = Add-TeamUser -GroupId $groupId -User $ownerToAdd.User -Role 'Owner'
				Write-Information "Successfully added User [$($ownerToAdd.User)] to Team Owners of [$groupId]"
			}
			catch{
				Write-Error "Could not add User [$($ownerToAdd.User)] to Team Owners of [$groupId]. Error: $($_.Exception.Message)"
			}
		}
	}
	
	if($OwnersToRemove -ne $null){
		Write-Warning "Starting to remove Users to Team Owners of [$groupId]: $($OwnersToRemove | Out-String)"
			
		foreach($ownerToRemove in $OwnersToRemove)
		{
			try{
				$username = $ownerToRemove.User
				$removeOwner = Remove-TeamUser -GroupId $groupId -User $ownerToRemove.User -Role 'Owner'
				Write-Information "Successfully removed User [$($ownerToRemove.User)] from Team Owners of [$groupId]"
			}
			catch{
				Write-Error "Could not remove User [$($ownerToRemove.User)] from Team Owners of [$groupId]. Error: $($_.Exception.Message)"
			}
		}   
	}
}
