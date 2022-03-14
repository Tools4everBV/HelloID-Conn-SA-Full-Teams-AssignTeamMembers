# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12
#HelloID variables
#Note: when running this script inside HelloID; portalUrl and API credentials are provided automatically (generate and save API credentials first in your admin panel!)
$portalUrl = "https://CUSTOMER.helloid.com"
$apiKey = "API_KEY"
$apiSecret = "API_SECRET"
$delegatedFormAccessGroupNames = @("Users") #Only unique names are supported. Groups must exist!
$delegatedFormCategories = @("Teams") #Only unique names are supported. Categories will be created if not exists
$script:debugLogging = $false #Default value: $false. If $true, the HelloID resource GUIDs will be shown in the logging
$script:duplicateForm = $false #Default value: $false. If $true, the HelloID resource names will be changed to import a duplicate Form
$script:duplicateFormSuffix = "_tmp" #the suffix will be added to all HelloID resource names to generate a duplicate form with different resource names

#The following HelloID Global variables are used by this form. No existing HelloID global variables will be overriden only new ones are created.
#NOTE: You can also update the HelloID Global variable values afterwards in the HelloID Admin Portal: https://<CUSTOMER>.helloid.com/admin/variablelibrary
$globalHelloIDVariables = [System.Collections.Generic.List[object]]@();

#Global variable #1 >> TeamsAdminUser
$tmpName = @'
TeamsAdminUser
'@ 
$tmpValue = @'
ramon@schoulens.onmicrosoft.com
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});

#Global variable #2 >> TeamsAdminPWD
$tmpName = @'
TeamsAdminPWD
'@ 
$tmpValue = "" 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "True"});


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
            $body = ConvertTo-Json -InputObject $body
    
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
            $body = ConvertTo-Json -InputObject $body
    
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
            $body = ConvertTo-Json -InputObject $body
      
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
        [parameter()][String][AllowEmptyString()]$AccessGroups,
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
                accessGroups    = (ConvertFrom-Json-WithEmptyArray($AccessGroups));
                useFaIcon       = $UseFaIcon;
                faIcon          = $FaIcon;
                task            = ConvertFrom-Json -inputObject $task;
            }    
            $body = ConvertTo-Json -InputObject $body
    
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
<# Begin: DataSource "Assign-Team-Members-Teams-get-azure-users" #>
$tmpPsScript = @'
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
'@ 
$tmpModel = @'
[{"key":"Name","type":0},{"key":"User","type":0}]
'@ 
$tmpInput = @'
[]
'@ 
$dataSourceGuid_2 = [PSCustomObject]@{} 
$dataSourceGuid_2_Name = @'
Assign-Team-Members-Teams-get-azure-users
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_2_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_2) 
<# End: DataSource "Assign-Team-Members-Teams-get-azure-users" #>

<# Begin: DataSource "Assign-Team-Members-Teams-get-teams" #>
$tmpPsScript = @'
#Input: TeamsAdminUser
#Input: TeamsAdminPWD

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

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
	    $teams = Get-Team
        Write-Information "Result count: $(@($teams).Count)"

        if(@($teams).Count -gt 0){
            foreach($team in $teams)
            {
                $resultObject = @{DisplayName=$team.DisplayName; Description=$team.Description; MailNickName=$team.MailNickName; Visibility=$team.Visibility; Archived=$team.Archived; GroupId=$team.GroupId;}
                Write-Output $resultObject
            }
        }
	}
	catch
	{
		Write-Error "Error getting Teams. Error: $($_.Exception.Message)"
	}
}

'@ 
$tmpModel = @'
[{"key":"GroupId","type":0},{"key":"Visibility","type":0},{"key":"DisplayName","type":0},{"key":"Description","type":0},{"key":"MailNickName","type":0},{"key":"Archived","type":0}]
'@ 
$tmpInput = @'
[]
'@ 
$dataSourceGuid_0 = [PSCustomObject]@{} 
$dataSourceGuid_0_Name = @'
Assign-Team-Members-Teams-get-teams
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_0_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_0) 
<# End: DataSource "Assign-Team-Members-Teams-get-teams" #>

<# Begin: DataSource "Assign-Team-Members-Teams-get-azure-owners" #>
$tmpPsScript = @'
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
'@ 
$tmpModel = @'
[{"key":"Name","type":0},{"key":"User","type":0},{"key":"UserId","type":0},{"key":"Role","type":0}]
'@ 
$tmpInput = @'
[{"description":null,"translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":1},{"description":null,"translateDescription":false,"inputFieldType":1,"key":"Role","type":0,"options":0}]
'@ 
$dataSourceGuid_3 = [PSCustomObject]@{} 
$dataSourceGuid_3_Name = @'
Assign-Team-Members-Teams-get-azure-owners
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_3_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_3) 
<# End: DataSource "Assign-Team-Members-Teams-get-azure-owners" #>

<# Begin: DataSource "Assign-Team-Members-Teams-get-azure-users" #>
$tmpPsScript = @'
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
'@ 
$tmpModel = @'
[{"key":"Name","type":0},{"key":"User","type":0}]
'@ 
$tmpInput = @'
[]
'@ 
$dataSourceGuid_4 = [PSCustomObject]@{} 
$dataSourceGuid_4_Name = @'
Assign-Team-Members-Teams-get-azure-users
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_4_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_4) 
<# End: DataSource "Assign-Team-Members-Teams-get-azure-users" #>

<# Begin: DataSource "Assign-Team-Members-Teams-get-azure-members" #>
$tmpPsScript = @'
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
'@ 
$tmpModel = @'
[{"key":"Name","type":0},{"key":"User","type":0},{"key":"UserId","type":0},{"key":"Role","type":0}]
'@ 
$tmpInput = @'
[{"description":null,"translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":1},{"description":null,"translateDescription":false,"inputFieldType":1,"key":"Role","type":0,"options":0}]
'@ 
$dataSourceGuid_1 = [PSCustomObject]@{} 
$dataSourceGuid_1_Name = @'
Assign-Team-Members-Teams-get-azure-members
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_1_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_1) 
<# End: DataSource "Assign-Team-Members-Teams-get-azure-members" #>
<# End: HelloID Data sources #>

<# Begin: Dynamic Form "Teams - Assign Team Members" #>
$tmpSchema = @"
[{"label":"Select Team","fields":[{"key":"teams","templateOptions":{"label":"Select team","required":true,"grid":{"columns":[{"headerName":"Display Name","field":"DisplayName"},{"headerName":"Description","field":"Description"},{"headerName":"Mail Nick Name","field":"MailNickName"},{"headerName":"Visibility","field":"Visibility"},{"headerName":"Archived","field":"Archived"},{"headerName":"Group Id","field":"GroupId"}],"height":300,"rowSelection":"single"},"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_0","input":{"propertyInputs":[]}},"useFilter":true,"useDefault":false},"type":"grid","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":true}]},{"label":"Assign Team Members","fields":[{"key":"members","templateOptions":{"label":"Members","required":false,"filterable":true,"useDataSource":true,"dualList":{"options":[{"guid":"75ea2890-88f8-4851-b202-626123054e14","Name":"Apple"},{"guid":"0607270d-83e2-4574-9894-0b70011b663f","Name":"Pear"},{"guid":"1ef6fe01-3095-4614-a6db-7c8cd416ae3b","Name":"Orange"}],"optionKeyProperty":"User","optionDisplayProperty":"Name"},"destinationDataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_1","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}},{"propertyName":"Role","staticValue":{"value":"Member"}}]}},"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_2","input":{"propertyInputs":[]}}},"type":"duallist","summaryVisibility":"Show","sourceDataSourceIdentifierSuffix":"source-datasource","destinationDataSourceIdentifierSuffix":"destination-datasource","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"owners","templateOptions":{"label":"Owners","required":false,"filterable":true,"useDataSource":true,"dualList":{"options":[{"guid":"75ea2890-88f8-4851-b202-626123054e14","Name":"Apple"},{"guid":"0607270d-83e2-4574-9894-0b70011b663f","Name":"Pear"},{"guid":"1ef6fe01-3095-4614-a6db-7c8cd416ae3b","Name":"Orange"}],"optionKeyProperty":"User","optionDisplayProperty":"Name"},"destinationDataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_3","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}},{"propertyName":"Role","staticValue":{"value":"Owner"}}]}},"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_4","input":{"propertyInputs":[]}}},"type":"duallist","summaryVisibility":"Show","sourceDataSourceIdentifierSuffix":"source-datasource","destinationDataSourceIdentifierSuffix":"destination-datasource","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false}]}]
"@ 

$dynamicFormGuid = [PSCustomObject]@{} 
$dynamicFormName = @'
Teams - Assign Team Members
'@ 
Invoke-HelloIDDynamicForm -FormName $dynamicFormName -FormSchema $tmpSchema  -returnObject ([Ref]$dynamicFormGuid) 
<# END: Dynamic Form #>

<# Begin: Delegated Form Access Groups and Categories #>
$delegatedFormAccessGroupGuids = @()
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
$delegatedFormAccessGroupGuids = ($delegatedFormAccessGroupGuids | Select-Object -Unique | ConvertTo-Json -Compress)
$delegatedFormCategoryGuids = @()
foreach($category in $delegatedFormCategories) {
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/delegatedformcategories/$category")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        $tmpGuid = $response.delegatedFormCategoryGuid
        $delegatedFormCategoryGuids += $tmpGuid
        
        Write-Information "HelloID Delegated Form category '$category' successfully found$(if ($script:debugLogging -eq $true) { ": " + $tmpGuid })"
    } catch {
        Write-Warning "HelloID Delegated Form category '$category' not found"
        $body = @{
            name = @{"en" = $category};
        }
        $body = ConvertTo-Json -InputObject $body
        $uri = ($script:PortalBaseUrl +"api/v1/delegatedformcategories")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
        $tmpGuid = $response.delegatedFormCategoryGuid
        $delegatedFormCategoryGuids += $tmpGuid
        Write-Information "HelloID Delegated Form category '$category' successfully created$(if ($script:debugLogging -eq $true) { ": " + $tmpGuid })"
    }
}
$delegatedFormCategoryGuids = (ConvertTo-Json -InputObject $delegatedFormCategoryGuids -Compress)
<# End: Delegated Form Access Groups and Categories #>

<# Begin: Delegated Form #>
$delegatedFormRef = [PSCustomObject]@{guid = $null; created = $null} 
$delegatedFormName = @'
Teams - Assign Team Members
'@
$tmpTask = @'
{"name":"Teams - Assign Team Members","script":"#Input: TeamsAdminUser\r\n#Input: TeamsAdminPWD\r\n\r\n# Set TLS to accept TLS, TLS 1.1 and TLS 1.2\r\n[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12\r\n\r\n$VerbosePreference = \"SilentlyContinue\"\r\n$InformationPreference = \"Continue\"\r\n$WarningPreference = \"Continue\"\r\n\r\n# variables configured in form\r\n$groupId = $form.teams.GroupId\r\n$MembersToAdd = $form.members.leftToRight\r\n$MembersToRemove = $form.members.rightToLeft\r\n$OwnersToAdd = $form.owners.leftToRight\r\n$OwnersToRemove = $form.Owners.rightToLeft\r\n\r\n$connected = $false\r\ntry {\r\n\t$module = Import-Module MicrosoftTeams -Verbose:$false\r\n\t$pwd = ConvertTo-SecureString -string $TeamsAdminPWD -AsPlainText -Force\r\n\t$cred = New-Object System.Management.Automation.PSCredential $TeamsAdminUser, $pwd\r\n\t$teamsConnection = Connect-MicrosoftTeams -Credential $cred -Verbose:$false\r\n    Write-Information \"Connected to Microsoft Teams\"\r\n    $connected = $true\r\n}\r\ncatch\r\n{\t\r\n    Write-Error \"Could not connect to Microsoft Teams. Error: $($_.Exception.Message)\"\r\n}\r\n\r\nif ($connected)\r\n{\r\n\tif($MembersToAdd -ne $null){\r\n\t\tWrite-Warning \"Starting to add Users to Team Members of [$groupId]: $($MembersToAdd | Out-String)\"\r\n\t\t\r\n\t\tforeach($memberToAdd in $MembersToAdd)\r\n\t\t{\r\n\t\t\ttry{\r\n\t\t\t\t$addMember = Add-TeamUser -GroupId $groupId -User $memberToAdd.User -Role 'Member'\r\n\t\t\t\tWrite-Information \"Successfully added User [$($memberToAdd.User)] to Team Members of [$groupId]\"\r\n\t\t\t}\r\n\t\t\tcatch{\r\n\t\t\t\tWrite-Error \"Could not add User [$($memberToAdd.User)] to Team Members of [$groupId]. Error: $($_.Exception.Message)\"\r\n            }\r\n\t\t}\r\n\t}\r\n\t\r\n\tif($MembersToRemove -ne $null){\r\n\t\tWrite-Warning \"Starting to remove Users to Team Members of [$groupId]: $($MembersToRemove | Out-String)\"\r\n\t\t$usersToRemoveJson =  $MembersToRemove | ConvertFrom-Json\r\n\t\t\t\r\n\t\tforeach($memberToRemove in $MembersToRemove)\r\n\t\t{\r\n\t\t\ttry{\r\n\t\t\t\t$removeMember = Remove-TeamUser -GroupId $groupId -User $memberToRemove.User\r\n                Write-Information \"Successfully removed User [$($memberToRemove.User)] from Team Members of [$groupId]\"\r\n\t\t\t}\r\n\t\t\tcatch{\r\n\t\t\t\tWirte-Error \"Could not remove User [$($memberToRemove.User)] from Team Members of [$groupId]. Error: $($_.Exception.Message)\"\r\n            }\r\n\t\t}   \r\n\t}\r\n\t\r\n\tif($OwnersToAdd -ne $null){\r\n\t\tWrite-Warning \"Starting to add Users to Team Owners of [$groupId]: $($OwnersToAdd | Out-String)\"\r\n\t\t\r\n\t\tforeach($ownerToAdd in $OwnersToAdd)\r\n\t\t{\r\n\t\t\ttry{\r\n\t\t\t\t$addOwner = Add-TeamUser -GroupId $groupId -User $ownerToAdd.User -Role 'Owner'\r\n\t\t\t\tWrite-Information \"Successfully added User [$($ownerToAdd.User)] to Team Owners of [$groupId]\"\r\n\t\t\t}\r\n\t\t\tcatch{\r\n\t\t\t\tWrite-Error \"Could not add User [$($ownerToAdd.User)] to Team Owners of [$groupId]. Error: $($_.Exception.Message)\"\r\n\t\t\t}\r\n\t\t}\r\n\t}\r\n\t\r\n\tif($OwnersToRemove -ne $null){\r\n\t\tWrite-Warning \"Starting to remove Users to Team Owners of [$groupId]: $($OwnersToRemove | Out-String)\"\r\n\t\t\t\r\n\t\tforeach($ownerToRemove in $OwnersToRemove)\r\n\t\t{\r\n\t\t\ttry{\r\n\t\t\t\t$username = $ownerToRemove.User\r\n\t\t\t\t$removeOwner = Remove-TeamUser -GroupId $groupId -User $ownerToRemove.User -Role 'Owner'\r\n\t\t\t\tWrite-Information \"Successfully removed User [$($ownerToRemove.User)] from Team Owners of [$groupId]\"\r\n\t\t\t}\r\n\t\t\tcatch{\r\n\t\t\t\tWrite-Error \"Could not remove User [$($ownerToRemove.User)] from Team Owners of [$groupId]. Error: $($_.Exception.Message)\"\r\n\t\t\t}\r\n\t\t}   \r\n\t}\r\n}","runInCloud":false}
'@ 

Invoke-HelloIDDelegatedForm -DelegatedFormName $delegatedFormName -DynamicFormGuid $dynamicFormGuid -AccessGroups $delegatedFormAccessGroupGuids -Categories $delegatedFormCategoryGuids -UseFaIcon "True" -FaIcon "fa fa-pencil-square-o" -task $tmpTask -returnObject ([Ref]$delegatedFormRef) 
<# End: Delegated Form #>

