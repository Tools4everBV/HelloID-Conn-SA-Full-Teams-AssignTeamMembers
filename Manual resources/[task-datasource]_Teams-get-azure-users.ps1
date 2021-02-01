$connected = $false
try {
	Import-Module AzureAD
	$pwd = ConvertTo-SecureString -string $TeamsAdminPWD -AsPlainText -Force
	$cred = New-Object System.Management.Automation.PSCredential $TeamsAdminUser, $pwd
	Connect-AzureAD -Credential $cred
    HID-Write-Status -Message "Connected to Microsoft Azure" -Event Information
    HID-Write-Summary -Message "Connected to Microsoft Azure" -Event Information
	$connected = $true
}
catch
{	
    HID-Write-Status -Message "Could not connect to Microsoft Azure. Error: $($_.Exception.Message)" -Event Error
    HID-Write-Summary -Message "Failed to connect to Microsoft Azure" -Event Failed
}

if ($connected)
{
	try {
		$users = Get-AzureADUser | Sort-Object name

		if(@($users).Count -gt 0){
			foreach($user in $users)
			{
				$userDescription = @{User=$user.UserPrincipalName; Name=$user.displayName;}
				Hid-Add-TaskResult -ResultValue $userDescription
			}
		}else{
			Hid-Add-TaskResult -ResultValue []
		}
	}
	catch
	{
		HID-Write-Status -Message "Error searching Azure. Error: $($_.Exception.Message)" -Event Error
		HID-Write-Summary -Message "Error searching Azure" -Event Failed
		Hid-Add-TaskResult -ResultValue []
	}
}
else
{
	Hid-Add-TaskResult -ResultValue []
}
