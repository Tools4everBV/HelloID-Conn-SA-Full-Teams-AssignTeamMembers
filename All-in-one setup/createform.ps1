# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

#HelloID variables
#Note: when running this script inside HelloID; portalUrl and API credentials are provided automatically (generate and save API credentials first in your admin panel!)
$portalUrl = "https://CUSTOMER.helloid.com"
$apiKey = "API_KEY"
$apiSecret = "API_SECRET"
$delegatedFormAccessGroupNames = @("") #Only unique names are supported. Groups must exist!
$delegatedFormCategories = @("Teams") #Only unique names are supported. Categories will be created if not exists
$script:debugLogging = $false #Default value: $false. If $true, the HelloID resource GUIDs will be shown in the logging
$script:duplicateForm = $false #Default value: $false. If $true, the HelloID resource names will be changed to import a duplicate Form
$script:duplicateFormSuffix = "_tmp" #the suffix will be added to all HelloID resource names to generate a duplicate form with different resource names

#The following HelloID Global variables are used by this form. No existing HelloID global variables will be overriden only new ones are created.
#NOTE: You can also update the HelloID Global variable values afterwards in the HelloID Admin Portal: https://<CUSTOMER>.helloid.com/admin/variablelibrary
$globalHelloIDVariables = [System.Collections.Generic.List[object]]@();

#Global variable #1 >> AADAppId
$tmpName = @'
AADAppId
'@ 
$tmpValue = ""
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});

#Global variable #2 >> AADAppSecret
$tmpName = @'
AADAppSecret
'@ 
$tmpValue = "" 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});

#Global variable #3 >> TeamsAdminUser
$tmpName = @'
TeamsAdminUser
'@ 
$tmpValue = "" 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});

#Global variable #4 >> TeamsAdminPWD
$tmpName = @'
AADtenantID
'@ 
$tmpValue = ""  
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});


#make sure write-information logging is visual
$InformationPreference = "continue"

# Check for prefilled API Authorization header
if (-not [string]::IsNullOrEmpty($portalApiBasic)) {
    $script:headers = @{"authorization" = $portalApiBasic}
    Write-Information "Using prefilled API credentials"
} else {
    # Create authorization headers with HelloID API key
    $pair = "$apiKey" + ":" + "$apiSecret"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $base64 = [System.Convert]::ToBase64String($bytes)
    $key = "Basic $base64"
    $script:headers = @{"authorization" = $Key}
    Write-Information "Using manual API credentials"
}

# Check for prefilled PortalBaseURL
if (-not [string]::IsNullOrEmpty($portalBaseUrl)) {
    $script:PortalBaseUrl = $portalBaseUrl
    Write-Information "Using prefilled PortalURL: $script:PortalBaseUrl"
} else {
    $script:PortalBaseUrl = $portalUrl
    Write-Information "Using manual PortalURL: $script:PortalBaseUrl"
}

# Define specific endpoint URI
$script:PortalBaseUrl = $script:PortalBaseUrl.trim("/") + "/"  

# Make sure to reveive an empty array using PowerShell Core
function ConvertFrom-Json-WithEmptyArray([string]$jsonString) {
    # Running in PowerShell Core?
    if($IsCoreCLR -eq $true){
        $r = [Object[]]($jsonString | ConvertFrom-Json -NoEnumerate)
        return ,$r  # Force return value to be an array using a comma
    } else {
        $r = [Object[]]($jsonString | ConvertFrom-Json)
        return ,$r  # Force return value to be an array using a comma
    }
}

function Invoke-HelloIDGlobalVariable {
    param(
        [parameter(Mandatory)][String]$Name,
        [parameter(Mandatory)][String][AllowEmptyString()]$Value,
        [parameter(Mandatory)][String]$Secret
    )

    $Name = $Name + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        $uri = ($script:PortalBaseUrl + "api/v1/automation/variables/named/$Name")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
    
        if ([string]::IsNullOrEmpty($response.automationVariableGuid)) {
            #Create Variable
            $body = @{
                name     = $Name;
                value    = $Value;
                secret   = $Secret;
                ItemType = 0;
            }    
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl + "api/v1/automation/variable")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
            $variableGuid = $response.automationVariableGuid

            Write-Information "Variable '$Name' created$(if ($script:debugLogging -eq $true) { ": " + $variableGuid })"
        } else {
            $variableGuid = $response.automationVariableGuid
            Write-Warning "Variable '$Name' already exists$(if ($script:debugLogging -eq $true) { ": " + $variableGuid })"
        }
    } catch {
        Write-Error "Variable '$Name', message: $_"
    }
}

function Invoke-HelloIDAutomationTask {
    param(
        [parameter(Mandatory)][String]$TaskName,
        [parameter(Mandatory)][String]$UseTemplate,
        [parameter(Mandatory)][String]$AutomationContainer,
        [parameter(Mandatory)][String][AllowEmptyString()]$Variables,
        [parameter(Mandatory)][String]$PowershellScript,
        [parameter()][String][AllowEmptyString()]$ObjectGuid,
        [parameter()][String][AllowEmptyString()]$ForceCreateTask,
        [parameter(Mandatory)][Ref]$returnObject
    )
    
    $TaskName = $TaskName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        $uri = ($script:PortalBaseUrl +"api/v1/automationtasks?search=$TaskName&container=$AutomationContainer")
        $responseRaw = (Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false) 
        $response = $responseRaw | Where-Object -filter {$_.name -eq $TaskName}
    
        if([string]::IsNullOrEmpty($response.automationTaskGuid) -or $ForceCreateTask -eq $true) {
            #Create Task

            $body = @{
                name                = $TaskName;
                useTemplate         = $UseTemplate;
                powerShellScript    = $PowershellScript;
                automationContainer = $AutomationContainer;
                objectGuid          = $ObjectGuid;
                variables           = (ConvertFrom-Json-WithEmptyArray($Variables));
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl +"api/v1/automationtasks/powershell")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
            $taskGuid = $response.automationTaskGuid

            Write-Information "Powershell task '$TaskName' created$(if ($script:debugLogging -eq $true) { ": " + $taskGuid })"
        } else {
            #Get TaskGUID
            $taskGuid = $response.automationTaskGuid
            Write-Warning "Powershell task '$TaskName' already exists$(if ($script:debugLogging -eq $true) { ": " + $taskGuid })"
        }
    } catch {
        Write-Error "Powershell task '$TaskName', message: $_"
    }

    $returnObject.Value = $taskGuid
}

function Invoke-HelloIDDatasource {
    param(
        [parameter(Mandatory)][String]$DatasourceName,
        [parameter(Mandatory)][String]$DatasourceType,
        [parameter(Mandatory)][String][AllowEmptyString()]$DatasourceModel,
        [parameter()][String][AllowEmptyString()]$DatasourceStaticValue,
        [parameter()][String][AllowEmptyString()]$DatasourcePsScript,        
        [parameter()][String][AllowEmptyString()]$DatasourceInput,
        [parameter()][String][AllowEmptyString()]$AutomationTaskGuid,
        [parameter(Mandatory)][Ref]$returnObject
    )

    $DatasourceName = $DatasourceName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    $datasourceTypeName = switch($DatasourceType) { 
        "1" { "Native data source"; break} 
        "2" { "Static data source"; break} 
        "3" { "Task data source"; break} 
        "4" { "Powershell data source"; break}
    }
    
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/datasource/named/$DatasourceName")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
      
        if([string]::IsNullOrEmpty($response.dataSourceGUID)) {
            #Create DataSource
            $body = @{
                name               = $DatasourceName;
                type               = $DatasourceType;
                model              = (ConvertFrom-Json-WithEmptyArray($DatasourceModel));
                automationTaskGUID = $AutomationTaskGuid;
                value              = (ConvertFrom-Json-WithEmptyArray($DatasourceStaticValue));
                script             = $DatasourcePsScript;
                input              = (ConvertFrom-Json-WithEmptyArray($DatasourceInput));
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
      
            $uri = ($script:PortalBaseUrl +"api/v1/datasource")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
              
            $datasourceGuid = $response.dataSourceGUID
            Write-Information "$datasourceTypeName '$DatasourceName' created$(if ($script:debugLogging -eq $true) { ": " + $datasourceGuid })"
        } else {
            #Get DatasourceGUID
            $datasourceGuid = $response.dataSourceGUID
            Write-Warning "$datasourceTypeName '$DatasourceName' already exists$(if ($script:debugLogging -eq $true) { ": " + $datasourceGuid })"
        }
    } catch {
      Write-Error "$datasourceTypeName '$DatasourceName', message: $_"
    }

    $returnObject.Value = $datasourceGuid
}

function Invoke-HelloIDDynamicForm {
    param(
        [parameter(Mandatory)][String]$FormName,
        [parameter(Mandatory)][String]$FormSchema,
        [parameter(Mandatory)][Ref]$returnObject
    )
    
    $FormName = $FormName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/forms/$FormName")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        } catch {
            $response = $null
        }
    
        if(([string]::IsNullOrEmpty($response.dynamicFormGUID)) -or ($response.isUpdated -eq $true)) {
            #Create Dynamic form
            $body = @{
                Name       = $FormName;
                FormSchema = (ConvertFrom-Json-WithEmptyArray($FormSchema));
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl +"api/v1/forms")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
    
            $formGuid = $response.dynamicFormGUID
            Write-Information "Dynamic form '$formName' created$(if ($script:debugLogging -eq $true) { ": " + $formGuid })"
        } else {
            $formGuid = $response.dynamicFormGUID
            Write-Warning "Dynamic form '$FormName' already exists$(if ($script:debugLogging -eq $true) { ": " + $formGuid })"
        }
    } catch {
        Write-Error "Dynamic form '$FormName', message: $_"
    }

    $returnObject.Value = $formGuid
}


function Invoke-HelloIDDelegatedForm {
    param(
        [parameter(Mandatory)][String]$DelegatedFormName,
        [parameter(Mandatory)][String]$DynamicFormGuid,
        [parameter()][Array][AllowEmptyString()]$AccessGroups,
        [parameter()][String][AllowEmptyString()]$Categories,
        [parameter(Mandatory)][String]$UseFaIcon,
        [parameter()][String][AllowEmptyString()]$FaIcon,
        [parameter()][String][AllowEmptyString()]$task,
        [parameter(Mandatory)][Ref]$returnObject
    )
    $delegatedFormCreated = $false
    $DelegatedFormName = $DelegatedFormName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms/$DelegatedFormName")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        } catch {
            $response = $null
        }
    
        if([string]::IsNullOrEmpty($response.delegatedFormGUID)) {
            #Create DelegatedForm
            $body = @{
                name            = $DelegatedFormName;
                dynamicFormGUID = $DynamicFormGuid;
                isEnabled       = "True";
                useFaIcon       = $UseFaIcon;
                faIcon          = $FaIcon;
                task            = ConvertFrom-Json -inputObject $task;
            }
            if(-not[String]::IsNullOrEmpty($AccessGroups)) { 
                $body += @{
                    accessGroups    = (ConvertFrom-Json-WithEmptyArray($AccessGroups));
                }
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
    
            $delegatedFormGuid = $response.delegatedFormGUID
            Write-Information "Delegated form '$DelegatedFormName' created$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormGuid })"
            $delegatedFormCreated = $true

            $bodyCategories = $Categories
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms/$delegatedFormGuid/categories")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $bodyCategories
            Write-Information "Delegated form '$DelegatedFormName' updated with categories"
        } else {
            #Get delegatedFormGUID
            $delegatedFormGuid = $response.delegatedFormGUID
            Write-Warning "Delegated form '$DelegatedFormName' already exists$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormGuid })"
        }
    } catch {
        Write-Error "Delegated form '$DelegatedFormName', message: $_"
    }

    $returnObject.value.guid = $delegatedFormGuid
    $returnObject.value.created = $delegatedFormCreated
}


<# Begin: HelloID Global Variables #>
foreach ($item in $globalHelloIDVariables) {
	Invoke-HelloIDGlobalVariable -Name $item.name -Value $item.value -Secret $item.secret 
}
<# End: HelloID Global Variables #>


<# Begin: HelloID Data sources #>
<# Begin: DataSource "Teams-get-team-users" #>
$tmpPsScript = @'
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
'@ 
$tmpModel = @'
[{"key":"DisplayName","type":0},{"key":"Mailaddress","type":0},{"key":"Roles","type":0},{"key":"Id","type":0}]
'@ 
$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":1},{"description":null,"translateDescription":false,"inputFieldType":1,"key":"selectedRole","type":0,"options":1}]
'@ 
$dataSourceGuid_3 = [PSCustomObject]@{} 
$dataSourceGuid_3_Name = @'
Teams-get-team-users
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_3_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_3) 
<# End: DataSource "Teams-get-team-users" #>

<# Begin: DataSource "Teams-get-team-users" #>
$tmpPsScript = @'
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
'@ 
$tmpModel = @'
[{"key":"DisplayName","type":0},{"key":"Mailaddress","type":0},{"key":"Roles","type":0},{"key":"Id","type":0}]
'@ 
$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":1},{"description":null,"translateDescription":false,"inputFieldType":1,"key":"selectedRole","type":0,"options":1}]
'@ 
$dataSourceGuid_1 = [PSCustomObject]@{} 
$dataSourceGuid_1_Name = @'
Teams-get-team-users
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_1_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_1) 
<# End: DataSource "Teams-get-team-users" #>

<# Begin: DataSource "Teams-get-azure-users" #>
$tmpPsScript = @'
# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

try {
        Write-Information "Generating Microsoft Graph API Access Token user.."

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

        $propertiesToSelect = @(
            "UserPrincipalName",
            "GivenName",
            "Surname",
            "EmployeeId",
            "AccountEnabled",
            "DisplayName",
            "OfficeLocation",
            "Department",
            "JobTitle",
            "Mail",
            "MailNickName",
            "Id",
            "assignedLicenses",
            "assignedPlans"
        )
 
        $usersUri = "https://graph.microsoft.com/v1.0/users"                
        $usersUri = $usersUri + ('?$select=' + ($propertiesToSelect -join "," | Out-String))
        
        $data = @()
        $query = Invoke-RestMethod -Method Get -Uri $usersUri -Headers $authorization -ContentType 'application/x-www-form-urlencoded'
        $data += $query.value
        
        while($query.'@odata.nextLink' -ne $null){
            $query = Invoke-RestMethod -Method Get -Uri $query.'@odata.nextLink' -Headers $authorization -ContentType 'application/x-www-form-urlencoded'
            $data += $query.value 
        }
        
        $users = $data | Sort-Object -Property Name
        $resultCount = @($users).Count
        Write-Information "Result count: $resultCount"        
          
        if($resultCount -gt 0){
            foreach($user in $users){   
                if($user.assignedLicenses.count -gt 0) {
                    if($user.UserPrincipalName -ne $TeamsAdminUser)
                    {                        
                        $returnObject = @{Id=$user.id; User=$user.UserPrincipalName; DisplayName=$user.displayName }
                        Write-Output $returnObject
                    }
                }
            }
        } else {
            return
        }
    }
 catch {
    $errorDetailsMessage = ($_.ErrorDetails.Message | ConvertFrom-Json).error.message
    Write-Error ("Error searching for AzureAD groups. Error: $($_.Exception.Message)" + $errorDetailsMessage)
     
    return
}
'@ 
$tmpModel = @'
[{"key":"Id","type":0},{"key":"User","type":0},{"key":"DisplayName","type":0}]
'@ 
$tmpInput = @'
[]
'@ 
$dataSourceGuid_2 = [PSCustomObject]@{} 
$dataSourceGuid_2_Name = @'
Teams-get-azure-users
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_2_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_2) 
<# End: DataSource "Teams-get-azure-users" #>

<# Begin: DataSource "Teams-get-azure-users" #>
$tmpPsScript = @'
# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

try {
        Write-Information "Generating Microsoft Graph API Access Token user.."

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

        $propertiesToSelect = @(
            "UserPrincipalName",
            "GivenName",
            "Surname",
            "EmployeeId",
            "AccountEnabled",
            "DisplayName",
            "OfficeLocation",
            "Department",
            "JobTitle",
            "Mail",
            "MailNickName",
            "Id",
            "assignedLicenses",
            "assignedPlans"
        )
 
        $usersUri = "https://graph.microsoft.com/v1.0/users"                
        $usersUri = $usersUri + ('?$select=' + ($propertiesToSelect -join "," | Out-String))
        
        $data = @()
        $query = Invoke-RestMethod -Method Get -Uri $usersUri -Headers $authorization -ContentType 'application/x-www-form-urlencoded'
        $data += $query.value
        
        while($query.'@odata.nextLink' -ne $null){
            $query = Invoke-RestMethod -Method Get -Uri $query.'@odata.nextLink' -Headers $authorization -ContentType 'application/x-www-form-urlencoded'
            $data += $query.value 
        }
        
        $users = $data | Sort-Object -Property Name
        $resultCount = @($users).Count
        Write-Information "Result count: $resultCount"        
          
        if($resultCount -gt 0){
            foreach($user in $users){   
                if($user.assignedLicenses.count -gt 0) {
                    if($user.UserPrincipalName -ne $TeamsAdminUser)
                    {                        
                        $returnObject = @{Id=$user.id; User=$user.UserPrincipalName; DisplayName=$user.displayName }
                        Write-Output $returnObject
                    }
                }
            }
        } else {
            return
        }
    }
 catch {
    $errorDetailsMessage = ($_.ErrorDetails.Message | ConvertFrom-Json).error.message
    Write-Error ("Error searching for AzureAD groups. Error: $($_.Exception.Message)" + $errorDetailsMessage)
     
    return
}
'@ 
$tmpModel = @'
[{"key":"Id","type":0},{"key":"User","type":0},{"key":"DisplayName","type":0}]
'@ 
$tmpInput = @'
[]
'@ 
$dataSourceGuid_4 = [PSCustomObject]@{} 
$dataSourceGuid_4_Name = @'
Teams-get-azure-users
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_4_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_4) 
<# End: DataSource "Teams-get-azure-users" #>

<# Begin: DataSource "Teams-generate-table-wildcard" #>
$tmpPsScript = @'
# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

try {
    $searchValue = $datasource.searchValue
    $searchQuery = "*$searchValue*"
      
      
    if([String]::IsNullOrEmpty($searchValue) -eq $true){
        return
    }else{
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

        Write-Information -Message "Searching for: $searchQuery"
        #Add the authorization header to the request
        $authorization = @{
            Authorization = "Bearer $accesstoken";
            'Content-Type' = "application/json";
            Accept = "application/json";
        }
 
        $baseSearchUri = "https://graph.microsoft.com/"
        $searchUri = $baseSearchUri + "v1.0/groups" + "?`$filter=resourceProvisioningOptions/Any(x:x eq 'Team')"                        
        $teamsResponse = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false          

        $teams = foreach($teamObject in $teamsResponse.value){
            if($teamObject.displayName -like $searchQuery -or $teamObject.mailNickName -like $searchQuery){
                $teamObject
            }
        }

        $teams = $teams | Sort-Object -Property DisplayName
        $resultCount = @($teams).Count
        Write-Information -Message "Result count: $resultCount"
         
        if($resultCount -gt 0){
            foreach($team in $teams){
                $channelUri = $baseSearchUri + "v1.0/teams" + "/$($team.id)/channels"                
                $channel = Invoke-RestMethod -Uri $channelUri -Method Get -Headers $authorization -Verbose:$false
                $returnObject = @{DisplayName=$team.DisplayName; Description=$team.Description; MailNickName=$team.MailNickName; Mailaddress=$team.Mail; Visibility=$team.Visibility; GroupId=$team.Id}
                Write-Output $returnObject
            }
        } else {
            return
        }
    }
} catch {
    
    Write-Error -Message ("Error searching for Teams-enabled AzureAD groups. Error: $($_.Exception.Message)" + $errorDetailsMessage)
    Write-Warning -Message "Error searching for Teams-enabled AzureAD groups"
     
    return
}
'@ 
$tmpModel = @'
[{"key":"Visibility","type":0},{"key":"GroupId","type":0},{"key":"Mailaddress","type":0},{"key":"MailNickName","type":0},{"key":"DisplayName","type":0},{"key":"Description","type":0}]
'@ 
$tmpInput = @'
[{"description":null,"translateDescription":false,"inputFieldType":1,"key":"searchValue","type":0,"options":1}]
'@ 
$dataSourceGuid_0 = [PSCustomObject]@{} 
$dataSourceGuid_0_Name = @'
Teams-generate-table-wildcard
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_0_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_0) 
<# End: DataSource "Teams-generate-table-wildcard" #>
<# End: HelloID Data sources #>

<# Begin: Dynamic Form "Teams - Assign Team Members" #>
$tmpSchema = @"
[{"label":"Select Team","fields":[{"key":"searchValue","templateOptions":{"label":"Search for displayname","required":true},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"teams","templateOptions":{"label":"Select team","required":true,"grid":{"columns":[{"headerName":"Display Name","field":"DisplayName"},{"headerName":"Description","field":"Description"},{"headerName":"Mail Nick Name","field":"MailNickName"},{"headerName":"Mailaddress","field":"Mailaddress"},{"headerName":"Visibility","field":"Visibility"},{"headerName":"Group Id","field":"GroupId"}],"height":300,"rowSelection":"single"},"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_0","input":{"propertyInputs":[{"propertyName":"searchValue","otherFieldValue":{"otherFieldKey":"searchValue"}}]}},"useFilter":true,"useDefault":false},"type":"grid","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":true}]},{"label":"Assign Team Members","fields":[{"key":"members","templateOptions":{"label":"Members","required":false,"filterable":true,"useDataSource":true,"dualList":{"options":[{"guid":"75ea2890-88f8-4851-b202-626123054e14","Name":"Apple"},{"guid":"0607270d-83e2-4574-9894-0b70011b663f","Name":"Pear"},{"guid":"1ef6fe01-3095-4614-a6db-7c8cd416ae3b","Name":"Orange"}],"optionKeyProperty":"Id","optionDisplayProperty":"DisplayName","labelLeft":"Available","labelRight":"Current"},"destinationDataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_1","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}},{"propertyName":"selectedRole","staticValue":{"value":"Member"}}]}},"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_2","input":{"propertyInputs":[]}}},"type":"duallist","summaryVisibility":"Show","sourceDataSourceIdentifierSuffix":"source-datasource","destinationDataSourceIdentifierSuffix":"destination-datasource","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"owners","templateOptions":{"label":"Owners","required":false,"filterable":true,"useDataSource":true,"dualList":{"options":[{"guid":"75ea2890-88f8-4851-b202-626123054e14","Name":"Apple"},{"guid":"0607270d-83e2-4574-9894-0b70011b663f","Name":"Pear"},{"guid":"1ef6fe01-3095-4614-a6db-7c8cd416ae3b","Name":"Orange"}],"optionKeyProperty":"Id","optionDisplayProperty":"DisplayName","labelLeft":"Available","labelRight":"Current"},"destinationDataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_3","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}},{"propertyName":"selectedRole","staticValue":{"value":"Owner"}}]}},"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_4","input":{"propertyInputs":[]}}},"type":"duallist","summaryVisibility":"Show","sourceDataSourceIdentifierSuffix":"source-datasource","destinationDataSourceIdentifierSuffix":"destination-datasource","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false}]}]
"@ 

$dynamicFormGuid = [PSCustomObject]@{} 
$dynamicFormName = @'
Teams - Assign Team Members
'@ 
Invoke-HelloIDDynamicForm -FormName $dynamicFormName -FormSchema $tmpSchema  -returnObject ([Ref]$dynamicFormGuid) 
<# END: Dynamic Form #>

<# Begin: Delegated Form Access Groups and Categories #>
$delegatedFormAccessGroupGuids = @()
if(-not[String]::IsNullOrEmpty($delegatedFormAccessGroupNames)){
    foreach($group in $delegatedFormAccessGroupNames) {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/groups/$group")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
            $delegatedFormAccessGroupGuid = $response.groupGuid
            $delegatedFormAccessGroupGuids += $delegatedFormAccessGroupGuid
            
            Write-Information "HelloID (access)group '$group' successfully found$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormAccessGroupGuid })"
        } catch {
            Write-Error "HelloID (access)group '$group', message: $_"
        }
    }
    if($null -ne $delegatedFormAccessGroupGuids){
        $delegatedFormAccessGroupGuids = ($delegatedFormAccessGroupGuids | Select-Object -Unique | ConvertTo-Json -Depth 100 -Compress)
    }
}

$delegatedFormCategoryGuids = @()
foreach($category in $delegatedFormCategories) {
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/delegatedformcategories/$category")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        $response = $response | Where-Object {$_.name.en -eq $category}
        
        $tmpGuid = $response.delegatedFormCategoryGuid
        $delegatedFormCategoryGuids += $tmpGuid
        
        Write-Information "HelloID Delegated Form category '$category' successfully found$(if ($script:debugLogging -eq $true) { ": " + $tmpGuid })"
    } catch {
        Write-Warning "HelloID Delegated Form category '$category' not found"
        $body = @{
            name = @{"en" = $category};
        }
        $body = ConvertTo-Json -InputObject $body -Depth 100

        $uri = ($script:PortalBaseUrl +"api/v1/delegatedformcategories")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
        $tmpGuid = $response.delegatedFormCategoryGuid
        $delegatedFormCategoryGuids += $tmpGuid

        Write-Information "HelloID Delegated Form category '$category' successfully created$(if ($script:debugLogging -eq $true) { ": " + $tmpGuid })"
    }
}
$delegatedFormCategoryGuids = (ConvertTo-Json -InputObject $delegatedFormCategoryGuids -Depth 100 -Compress)
<# End: Delegated Form Access Groups and Categories #>

<# Begin: Delegated Form #>
$delegatedFormRef = [PSCustomObject]@{guid = $null; created = $null} 
$delegatedFormName = @'
Teams - Assign Team Members
'@
$tmpTask = @'
{"name":"Teams - Assign Team Members","script":"# Set TLS to accept TLS, TLS 1.1 and TLS 1.2\r\n[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12\r\n\r\n$VerbosePreference = \"SilentlyContinue\"\r\n$InformationPreference = \"Continue\"\r\n$WarningPreference = \"Continue\"\r\n\r\n$baseGraphUri = \"https://graph.microsoft.com\"\r\n\r\n# variables configured in form\r\n$groupId = $form.teams.GroupId\r\n$groupName = $form.teams.DisplayName\r\n$MembersToAdd = $form.members.leftToRight\r\n$MembersToRemove = $form.members.rightToLeft\r\n$OwnersToAdd = $form.owners.leftToRight\r\n$OwnersToRemove = $form.Owners.rightToLeft\r\n\r\n# Create authorization token and add to headers\r\ntry {\r\n    Write-Information \"Generating Microsoft Graph API Access Token\"\r\n\r\n    $baseUri = \"https://login.microsoftonline.com/\"\r\n    $authUri = $baseUri + \"$AADTenantID/oauth2/token\"\r\n\r\n    $body = @{\r\n        grant_type    = \"client_credentials\"\r\n        client_id     = \"$AADAppId\"\r\n        client_secret = \"$AADAppSecret\"\r\n        resource      = \"https://graph.microsoft.com\"\r\n    }\r\n\r\n    $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType \u0027application/x-www-form-urlencoded\u0027\r\n    $accessToken = $Response.access_token;\r\n\r\n    #Add the authorization header to the request\r\n    $authorization = @{\r\n        Authorization  = \"Bearer $accesstoken\";\r\n        \u0027Content-Type\u0027 = \"application/json\";\r\n        Accept         = \"application/json\";\r\n    }\r\n}\r\ncatch {\r\n    throw \"Could not generate Microsoft Graph API Access Token. Error: $($_.Exception.Message)\"    \r\n}\r\n\r\n$processUri = $baseGraphUri + \"/v1.0/teams/$groupId/members\"\r\n\r\nif ($MembersToAdd -ne $null) {\r\n    Write-Information \"Starting to add Users to Team Members of [$groupName].\"\r\n\t\t\r\n    foreach ($memberToAdd in $MembersToAdd) {\r\n        try {\r\n            $memberBody = @\"\r\n                {                \r\n                    \"`@odata.type\": \"#microsoft.graph.aadUserConversationMember\",\r\n                    \"roles\": [\"member\"],\r\n                    \"user@odata.bind\": \"$baseGraphUri/v1.0/users(\u0027$($memberToAdd.id)\u0027)\"\r\n                }\r\n\"@\r\n            $null = Invoke-RestMethod -Uri $processUri -Body $memberBody -Headers $authorization -Method POST\r\n            Write-Information \"Successfully added User [$($memberToAdd.User)] to Team Members of [$groupName]\"\r\n            $Log = @{\r\n                Action            = \"UpdateResource\" # optional. ENUM (undefined = default) \r\n                System            = \"AzureActiveDirectory\" # optional (free format text) \r\n                Message           = \"Successfully added User [$($memberToAdd.User)] to Team Members of [$groupName].\" # required (free format text) \r\n                IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n                TargetDisplayName = $groupName # optional (free format text)\r\n                TargetIdentifier  = $groupId # optional (free format text)\r\n            }\r\n            #send result back  \r\n            Write-Information -Tags \"Audit\" -MessageData $log\r\n        }\r\n        catch {\r\n            Write-Error \"Could not add User [$($memberToAdd.User)] to Team Members of [$groupName]. Error: $($_.Exception.Message)\"                \r\n            $Log = @{\r\n                Action            = \"UpdateResource\" # optional. ENUM (undefined = default) \r\n                System            = \"AzureActiveDirectory\" # optional (free format text) \r\n                Message           = \"Could not add User [$($memberToAdd.User)] to Team Members of [$groupName].\" # required (free format text) \r\n                IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n                TargetDisplayName = $groupName # optional (free format text)\r\n                TargetIdentifier  = $groupId # optional (free format text)\r\n            }\r\n            #send result back  \r\n            Write-Information -Tags \"Audit\" -MessageData $log\r\n        }\r\n    }\r\n}\r\n\r\n\t\r\n\r\nif ($MembersToRemove -ne $null) {\r\n    Write-Information \"Starting to remove Users from Team Members of [$groupName].\"\r\n    \t\t\r\n    foreach ($memberToRemove in $MembersToRemove) {\r\n        try {\r\n            $ResultMembers = (Invoke-RestMethod -Headers $authorization -Uri $processUri -Method Get).value | Where-Object userId -eq $($memberToRemove.id)\r\n            \r\n            $removeUri = $processUri + \"/\" + $($ResultMembers.id)\r\n            \r\n            $null = Invoke-RestMethod -Uri $removeUri -Headers $authorization -Method DELETE\r\n            Write-Information \"Successfully removed User [$($memberToRemove.User)] from Team Members of [$groupName]\"\r\n            $Log = @{\r\n                Action            = \"UpdateResource\" # optional. ENUM (undefined = default) \r\n                System            = \"AzureActiveDirectory\" # optional (free format text) \r\n                Message           = \"Successfully removed User [$($memberToRemove.User)] from Team Members of [$groupName].\" # required (free format text) \r\n                IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n                TargetDisplayName = $groupName # optional (free format text)\r\n                TargetIdentifier  = $groupId # optional (free format text)\r\n            }\r\n            #send result back  \r\n            Write-Information -Tags \"Audit\" -MessageData $log\r\n            \r\n        }\r\n        catch {\r\n             Write-Error \"Could not remove User [$($memberToAdd.User)] from Team Members of [$groupName]. Error: $($_.Exception.Message)\"                \r\n            $Log = @{\r\n                Action            = \"UpdateResource\" # optional. ENUM (undefined = default) \r\n                System            = \"AzureActiveDirectory\" # optional (free format text) \r\n                Message           = \"Could not remvoe User [$($memberToAdd.User)] to Team Members of [$groupName].\" # required (free format text) \r\n                IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n                TargetDisplayName = $groupName # optional (free format text)\r\n                TargetIdentifier  = $groupId # optional (free format text)\r\n            }\r\n            #send result back  \r\n            Write-Information -Tags \"Audit\" -MessageData $log\r\n        }\r\n    }   \r\n}\r\n\r\n\t\r\nif ($OwnersToAdd -ne $null) {\r\n    Write-Information \"Starting to add Users to Team Owners of [$groupName].\"\t\t\r\n\r\n    foreach ($ownerToAdd in $OwnersToAdd) {\r\n        try {\r\n            $memberBody = @\"\r\n                {                \r\n                    \"`@odata.type\": \"#microsoft.graph.aadUserConversationMember\",\r\n                    \"roles\": [\"owner\"],\r\n                    \"user@odata.bind\": \"$baseGraphUri/v1.0/users(\u0027$($ownerToAdd.id)\u0027)\"\r\n                }\r\n\"@\r\n            $null = Invoke-RestMethod -Uri $processUri -Body $memberBody -Headers $authorization -Method POST\r\n            Write-Information \"Successfully added User [$($ownerToAdd.User)] to Team Owners of [$groupName]\"\r\n            $Log = @{\r\n                Action            = \"UpdateResource\" # optional. ENUM (undefined = default) \r\n                System            = \"AzureActiveDirectory\" # optional (free format text) \r\n                Message           = \"Successfully added User [$($ownerToAdd.User)] to Team Owners of [$groupName].\" # required (free format text) \r\n                IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n                TargetDisplayName = $groupName # optional (free format text)\r\n                TargetIdentifier  = $groupId # optional (free format text)\r\n            }\r\n            #send result back  \r\n            Write-Information -Tags \"Audit\" -MessageData $log\r\n        }\r\n        catch {\r\n            Write-Error \"Could not add User [$($ownerToAdd.User)] to Team Owners of [$groupName]. Error: $($_.Exception.Message)\"\r\n            $Log = @{\r\n                Action            = \"UpdateResource\" # optional. ENUM (undefined = default) \r\n                System            = \"AzureActiveDirectory\" # optional (free format text) \r\n                Message           = \"Could not add User [$($ownerToAdd.User)] to Team Owners of [$groupName].\" # required (free format text) \r\n                IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n                TargetDisplayName = $groupName # optional (free format text)\r\n                TargetIdentifier  = $groupId # optional (free format text)\r\n            }\r\n            #send result back  \r\n            Write-Information -Tags \"Audit\" -MessageData $log\r\n        }\r\n    }\r\n}\r\n\t\r\n\r\nif ($OwnersToRemove -ne $null) {\r\n    Write-Information \"Starting to remove Users to Team Owners of [$groupName].\"\r\n        \r\n    foreach ($ownerToRemove in $OwnersToRemove) {\r\n        try {\r\n            $ResultMembers = (Invoke-RestMethod -Headers $authorization -Uri $processUri -Method Get).value | Where-Object userId -eq $($ownerToRemove.id)\r\n            \r\n            $removeUri = $processUri + \"/\" + $($ResultMembers.id)\r\n            \r\n            $null = Invoke-RestMethod -Uri $removeUri -Headers $authorization -Method DELETE\r\n            Write-Information \"Successfully removed User [$($ownerToRemove.User)] from Team Owners of [$groupName]\"\r\n            $Log = @{\r\n                Action            = \"UpdateResource\" # optional. ENUM (undefined = default) \r\n                System            = \"AzureActiveDirectory\" # optional (free format text) \r\n                Message           = \"Successfully removed User [$($ownerToRemove.User)] from Team Owners of [$groupName].\" # required (free format text) \r\n                IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n                TargetDisplayName = $groupName # optional (free format text)\r\n                TargetIdentifier  = $groupId # optional (free format text)\r\n            }\r\n            #send result back  \r\n            Write-Information -Tags \"Audit\" -MessageData $log\r\n            \r\n        }\r\n        catch {\r\n            Write-Information \"Could not remove User [$($ownerToRemove.User)] from Team Owners of [$groupName]\"\r\n            $Log = @{\r\n                Action            = \"UpdateResource\" # optional. ENUM (undefined = default) \r\n                System            = \"AzureActiveDirectory\" # optional (free format text) \r\n                Message           = \"Could not remove User [$($ownerToRemove.User)] from Team Owners of [$groupName].\" # required (free format text) \r\n                IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n                TargetDisplayName = $groupName # optional (free format text)\r\n                TargetIdentifier  = $groupId # optional (free format text)\r\n            }\r\n            #send result back  \r\n            Write-Information -Tags \"Audit\" -MessageData $log\r\n        }\r\n    }   \r\n}","runInCloud":false}
'@ 

Invoke-HelloIDDelegatedForm -DelegatedFormName $delegatedFormName -DynamicFormGuid $dynamicFormGuid -AccessGroups $delegatedFormAccessGroupGuids -Categories $delegatedFormCategoryGuids -UseFaIcon "True" -FaIcon "fa fa-pencil-square-o" -task $tmpTask -returnObject ([Ref]$delegatedFormRef) 
<# End: Delegated Form #>

