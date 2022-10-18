# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

$baseGraphUri = "https://graph.microsoft.com"

# variables configured in form
$groupId = $form.teams.GroupId
$groupName = $form.teams.DisplayName
$MembersToAdd = $form.members.leftToRight
$MembersToRemove = $form.members.rightToLeft
$OwnersToAdd = $form.owners.leftToRight
$OwnersToRemove = $form.Owners.rightToLeft

# Create authorization token and add to headers
try {
    Write-Information "Generating Microsoft Graph API Access Token"

    $baseUri = "https://login.microsoftonline.com/"
    $authUri = $baseUri + "$AADTenantID/oauth2/token"

    $body = @{
        grant_type    = "client_credentials"
        client_id     = "$AADAppId"
        client_secret = "$AADAppSecret"
        resource      = "https://graph.microsoft.com"
    }

    $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
    $accessToken = $Response.access_token;

    #Add the authorization header to the request
    $authorization = @{
        Authorization  = "Bearer $accesstoken";
        'Content-Type' = "application/json";
        Accept         = "application/json";
    }
}
catch {
    throw "Could not generate Microsoft Graph API Access Token. Error: $($_.Exception.Message)"    
}

$processUri = $baseGraphUri + "/v1.0/teams/$groupId/members"

if ($MembersToAdd -ne $null) {
    Write-Information "Starting to add Users to Team Members of [$groupName]."
		
    foreach ($memberToAdd in $MembersToAdd) {
        try {
            $memberBody = @"
                {                
                    "`@odata.type": "#microsoft.graph.aadUserConversationMember",
                    "roles": ["member"],
                    "user@odata.bind": "$baseGraphUri/v1.0/users('$($memberToAdd.id)')"
                }
"@
            $null = Invoke-RestMethod -Uri $processUri -Body $memberBody -Headers $authorization -Method POST
            Write-Information "Successfully added User [$($memberToAdd.User)] to Team Members of [$groupName]"
            $Log = @{
                Action            = "UpdateResource" # optional. ENUM (undefined = default) 
                System            = "AzureActiveDirectory" # optional (free format text) 
                Message           = "Successfully added User [$($memberToAdd.User)] to Team Members of [$groupName]." # required (free format text) 
                IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                TargetDisplayName = $groupName # optional (free format text)
                TargetIdentifier  = $groupId # optional (free format text)
            }
            #send result back  
            Write-Information -Tags "Audit" -MessageData $log
        }
        catch {
            Write-Error "Could not add User [$($memberToAdd.User)] to Team Members of [$groupName]. Error: $($_.Exception.Message)"                
            $Log = @{
                Action            = "UpdateResource" # optional. ENUM (undefined = default) 
                System            = "AzureActiveDirectory" # optional (free format text) 
                Message           = "Could not add User [$($memberToAdd.User)] to Team Members of [$groupName]." # required (free format text) 
                IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                TargetDisplayName = $groupName # optional (free format text)
                TargetIdentifier  = $groupId # optional (free format text)
            }
            #send result back  
            Write-Information -Tags "Audit" -MessageData $log
        }
    }
}

	

if ($MembersToRemove -ne $null) {
    Write-Information "Starting to remove Users from Team Members of [$groupName]."
    		
    foreach ($memberToRemove in $MembersToRemove) {
        try {
            $ResultMembers = (Invoke-RestMethod -Headers $authorization -Uri $processUri -Method Get).value | Where-Object userId -eq $($memberToRemove.id)
            
            $removeUri = $processUri + "/" + $($ResultMembers.id)
            
            $null = Invoke-RestMethod -Uri $removeUri -Headers $authorization -Method DELETE
            Write-Information "Successfully removed User [$($memberToRemove.User)] from Team Members of [$groupName]"
            $Log = @{
                Action            = "UpdateResource" # optional. ENUM (undefined = default) 
                System            = "AzureActiveDirectory" # optional (free format text) 
                Message           = "Successfully removed User [$($memberToRemove.User)] from Team Members of [$groupName]." # required (free format text) 
                IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                TargetDisplayName = $groupName # optional (free format text)
                TargetIdentifier  = $groupId # optional (free format text)
            }
            #send result back  
            Write-Information -Tags "Audit" -MessageData $log
            
        }
        catch {
             Write-Error "Could not remove User [$($memberToAdd.User)] from Team Members of [$groupName]. Error: $($_.Exception.Message)"                
            $Log = @{
                Action            = "UpdateResource" # optional. ENUM (undefined = default) 
                System            = "AzureActiveDirectory" # optional (free format text) 
                Message           = "Could not remvoe User [$($memberToAdd.User)] to Team Members of [$groupName]." # required (free format text) 
                IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                TargetDisplayName = $groupName # optional (free format text)
                TargetIdentifier  = $groupId # optional (free format text)
            }
            #send result back  
            Write-Information -Tags "Audit" -MessageData $log
        }
    }   
}

	
if ($OwnersToAdd -ne $null) {
    Write-Information "Starting to add Users to Team Owners of [$groupName]."		

    foreach ($ownerToAdd in $OwnersToAdd) {
        try {
            $memberBody = @"
                {                
                    "`@odata.type": "#microsoft.graph.aadUserConversationMember",
                    "roles": ["owner"],
                    "user@odata.bind": "$baseGraphUri/v1.0/users('$($ownerToAdd.id)')"
                }
"@
            $null = Invoke-RestMethod -Uri $processUri -Body $memberBody -Headers $authorization -Method POST
            Write-Information "Successfully added User [$($ownerToAdd.User)] to Team Owners of [$groupName]"
            $Log = @{
                Action            = "UpdateResource" # optional. ENUM (undefined = default) 
                System            = "AzureActiveDirectory" # optional (free format text) 
                Message           = "Successfully added User [$($ownerToAdd.User)] to Team Owners of [$groupName]." # required (free format text) 
                IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                TargetDisplayName = $groupName # optional (free format text)
                TargetIdentifier  = $groupId # optional (free format text)
            }
            #send result back  
            Write-Information -Tags "Audit" -MessageData $log
        }
        catch {
            Write-Error "Could not add User [$($ownerToAdd.User)] to Team Owners of [$groupName]. Error: $($_.Exception.Message)"
            $Log = @{
                Action            = "UpdateResource" # optional. ENUM (undefined = default) 
                System            = "AzureActiveDirectory" # optional (free format text) 
                Message           = "Could not add User [$($ownerToAdd.User)] to Team Owners of [$groupName]." # required (free format text) 
                IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                TargetDisplayName = $groupName # optional (free format text)
                TargetIdentifier  = $groupId # optional (free format text)
            }
            #send result back  
            Write-Information -Tags "Audit" -MessageData $log
        }
    }
}
	

if ($OwnersToRemove -ne $null) {
    Write-Information "Starting to remove Users to Team Owners of [$groupName]."
        
    foreach ($ownerToRemove in $OwnersToRemove) {
        try {
            $ResultMembers = (Invoke-RestMethod -Headers $authorization -Uri $processUri -Method Get).value | Where-Object userId -eq $($ownerToRemove.id)
            
            $removeUri = $processUri + "/" + $($ResultMembers.id)
            
            $null = Invoke-RestMethod -Uri $removeUri -Headers $authorization -Method DELETE
            Write-Information "Successfully removed User [$($ownerToRemove.User)] from Team Owners of [$groupName]"
            $Log = @{
                Action            = "UpdateResource" # optional. ENUM (undefined = default) 
                System            = "AzureActiveDirectory" # optional (free format text) 
                Message           = "Successfully removed User [$($ownerToRemove.User)] from Team Owners of [$groupName]." # required (free format text) 
                IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                TargetDisplayName = $groupName # optional (free format text)
                TargetIdentifier  = $groupId # optional (free format text)
            }
            #send result back  
            Write-Information -Tags "Audit" -MessageData $log
            
        }
        catch {
            Write-Information "Could not remove User [$($ownerToRemove.User)] from Team Owners of [$groupName]"
            $Log = @{
                Action            = "UpdateResource" # optional. ENUM (undefined = default) 
                System            = "AzureActiveDirectory" # optional (free format text) 
                Message           = "Could not remove User [$($ownerToRemove.User)] from Team Owners of [$groupName]." # required (free format text) 
                IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                TargetDisplayName = $groupName # optional (free format text)
                TargetIdentifier  = $groupId # optional (free format text)
            }
            #send result back  
            Write-Information -Tags "Audit" -MessageData $log
        }
    }   
}
