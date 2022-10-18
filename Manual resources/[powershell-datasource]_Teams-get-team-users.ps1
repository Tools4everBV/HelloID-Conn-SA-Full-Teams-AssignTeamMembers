$groupId = $datasource.selectedGroup.GroupId
$role = $datasource.selectedRole

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

try {    
          
        Write-Information -Message "Generating Microsoft Graph API Access Token user.."

        $baseUri = "https://login.microsoftonline.com/"
        $authUri = $baseUri + "$AADTenantID/oauth2/token"

        $body = @{
            grant_type      = "client_credentials"
            client_id       = "$AADAppId"
            client_secret   = "$AADAppSecret"
            resource        = "https://graph.microsoft.com"
        }
 
        $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
        $accessToken = $Response.access_token;

        #Add the authorization header to the request
        $authorization = @{
            Authorization = "Bearer $accesstoken";
            'Content-Type' = "application/json";
            Accept = "application/json";
        }
 
        $baseSearchUri = "https://graph.microsoft.com/"        
        $searchUri = $baseSearchUri + "v1.0/teams/$groupId/members"        
 
        Write-Information -Message "Getting members of the selected Team."
        $memberResponse = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false          

        if($role -eq "member"){            
            $members = $memberResponse.value | Where-Object { $_.roles -notin ("guest","owner") }
        }
        if($role -ne "member") {
            $members = $memberResponse.value | Where-Object { $_.roles -eq $role }
        }

        $members = $members | Sort-Object -Property DisplayName
        $resultCount = @($members).Count
        Write-Information -Message "Result count: $resultCount"

        if($resultCount -gt 0){
            foreach($member in $members){
                $returnObject = @{Id=$member.Userid; DisplayName=$member.DisplayName; Mailaddress=$member.email; Roles=$role }
                Write-Output $returnObject
            }
            
        } else {
            return
        }
    
} catch {
    
    Write-Error -Message ("Error searching for Team members with role $role. Error: $($_.Exception.Message)" + $errorDetailsMessage)
    Write-Warning -Message "Error searching for Team members with role $role."
     
    return
}
