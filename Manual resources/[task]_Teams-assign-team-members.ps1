HID-Write-Status -Message "Members to add: $MembersToAdd" -Event Information
HID-Write-Status -Message "Members to remove: $MembersToRemove" -Event Information
HID-Write-Status -Message "Owners to add: $OwnersToAdd" -Event Information
HID-Write-Status -Message "Owners to remove: $OwnersToRemove" -Event Information

$connected = $false
try {
	Import-Module MicrosoftTeams
	$pwd = ConvertTo-SecureString -string $TeamsAdminPWD -AsPlainText -Force
	$cred = New-Object System.Management.Automation.PSCredential $TeamsAdminUser, $pwd
	Connect-MicrosoftTeams -Credential $cred
    HID-Write-Status -Message "Connected to Microsoft Teams" -Event Information
    HID-Write-Summary -Message "Connected to Microsoft Teams" -Event Information
	$connected = $true
}
catch
{	
    HID-Write-Status -Message "Could not connect to Microsoft Teams. Error: $($_.Exception.Message)" -Event Error
    HID-Write-Summary -Message "Failed to connect to Microsoft Teams" -Event Failed
}

if ($connected)
{
	if($MembersToAdd -ne "[]"){
		HID-Write-Status -Message "Starting to add Users to Team Members of [$groupId]: $MembersToAdd" -Event Information
		$usersToAddJson =  $MembersToAdd | ConvertFrom-Json
		
		foreach($user in $usersToAddJson)
		{
			try{
				$username = $user.User
				Add-TeamUser -GroupId $groupId -User $username -Role 'Member'
				HID-Write-Status -Message "Finished adding User [$username] to Team Members of [$groupId]" -Event Success
				HID-Write-Summary -Message "Successfully added User [$username] to Team Members of [$groupId]" -Event Success
			}
			catch{
				HID-Write-Status -Message "Could not add User [$username] to Team Members of [$groupId]. Error: $($_.Exception.Message)" -Event Error
				HID-Write-Summary -Message "Failed to add User [$username] to Team Members of [$groupId]" -Event Failed
			}
		}
	}
	
	if($MembersToRemove -ne "[]"){
		HID-Write-Status -Message "Starting to remove Users to Team Members of [$groupId]: $MembersToRemove" -Event Information
		$usersToRemoveJson =  $MembersToRemove | ConvertFrom-Json
			
		foreach($user in $usersToRemoveJson)
		{
			try{
				$username = $user.User
				Remove-TeamUser -GroupId $groupId -User $username
				HID-Write-Status -Message "Finished removing User [$username] from Team Members of [$groupId]" -Event Success
				HID-Write-Summary -Message "Successfully removed User [$username] from Team Members of [$groupId]" -Event Success
			}
			catch{
				HID-Write-Status -Message "Could not remove User [$username] from Team Members of [$groupId]. Error: $($_.Exception.Message)" -Event Error
				HID-Write-Summary -Message "Failed to remove User [$username] from Team Members of [$groupId]" -Event Failed
			}
		}   
	}
	
	if($OwnersToAdd -ne "[]"){
		HID-Write-Status -Message "Starting to add Users to Team Owners of [$groupId]: $OwnersToAdd" -Event Information
		$usersToAddJson =  $OwnersToAdd | ConvertFrom-Json
		
		foreach($user in $usersToAddJson)
		{
			try{
				$username = $user.User
				Add-TeamUser -GroupId $groupId -User $username -Role 'Owner'
				HID-Write-Status -Message "Finished adding User [$username] to Team Owners of [$groupId]" -Event Success
				HID-Write-Summary -Message "Successfully added User [$username] to Team Owners of [$groupId]" -Event Success
			}
			catch{
				HID-Write-Status -Message "Could not add User [$username] to Team Owners of [$groupId]. Error: $($_.Exception.Message)" -Event Error
				HID-Write-Summary -Message "Failed to add User [$username] to Team Owners of [$groupId]" -Event Failed
			}
		}
	}
	
	if($OwnersToRemove -ne "[]"){
		HID-Write-Status -Message "Starting to remove Users to Team Owners of [$groupId]: $OwnersToRemove" -Event Information
		$usersToRemoveJson =  $OwnersToRemove | ConvertFrom-Json
			
		foreach($user in $usersToRemoveJson)
		{
			try{
				$username = $user.User
				Remove-TeamUser -GroupId $groupId -User $username -Role 'Owner'
				HID-Write-Status -Message "Finished removing User [$username] from Team Owners of [$groupId]" -Event Success
				HID-Write-Summary -Message "Successfully removed User [$username] from Team Owners of [$groupId]" -Event Success
			}
			catch{
				HID-Write-Status -Message "Could not remove User [$username] from Team Owners of [$groupId]. Error: $($_.Exception.Message)" -Event Error
				HID-Write-Summary -Message "Failed to remove User [$username] from Team Owners of [$groupId]" -Event Failed
			}
		}   
	}
}
