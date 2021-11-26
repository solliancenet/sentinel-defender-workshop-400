Param (
  [Parameter(Mandatory = $true)]
  [string]
  $azureUsername,

  [string]
  $azurePassword,

  [string]
  $azureTenantID,

  [string]
  $azureSubscriptionID,

  [string]
  $odlId,
    
  [string]
  $deploymentId
)

#Disable-InternetExplorerESC
function DisableInternetExplorerESC
{
  $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
  $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
  Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0 -Force -ErrorAction SilentlyContinue -Verbose
  Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0 -Force -ErrorAction SilentlyContinue -Verbose
  Write-Host "IE Enhanced Security Configuration (ESC) has been disabled." -ForegroundColor Green -Verbose
}

#Enable-InternetExplorer File Download
function EnableIEFileDownload
{
  $HKLM = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
  $HKCU = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
  Set-ItemProperty -Path $HKLM -Name "1803" -Value 0 -ErrorAction SilentlyContinue -Verbose
  Set-ItemProperty -Path $HKCU -Name "1803" -Value 0 -ErrorAction SilentlyContinue -Verbose
  Set-ItemProperty -Path $HKLM -Name "1604" -Value 0 -ErrorAction SilentlyContinue -Verbose
  Set-ItemProperty -Path $HKCU -Name "1604" -Value 0 -ErrorAction SilentlyContinue -Verbose
}

#Create-LabFilesDirectory
function CreateLabFilesDirectory
{
  New-Item -ItemType directory -Path C:\temp -force
  New-Item -ItemType directory -Path C:\LabFiles -force
}

#Create Azure Credential File on Desktop
function CreateCredFile($azureUsername, $azurePassword, $azureTenantID, $azureSubscriptionID, $deploymentId)
{
  $WebClient = New-Object System.Net.WebClient
  $WebClient.DownloadFile("https://raw.githubusercontent.com/solliancenet/azure-synapse-analytics-workshop-400/master/artifacts/environment-setup/spektra/AzureCreds.txt","C:\LabFiles\AzureCreds.txt")
  $WebClient.DownloadFile("https://raw.githubusercontent.com/solliancenet/azure-synapse-analytics-workshop-400/master/artifacts/environment-setup/spektra/AzureCreds.ps1","C:\LabFiles\AzureCreds.ps1")

  (Get-Content -Path "C:\LabFiles\AzureCreds.txt") | ForEach-Object {$_ -Replace "ClientIdValue", ""} | Set-Content -Path "C:\LabFiles\AzureCreds.ps1"
  (Get-Content -Path "C:\LabFiles\AzureCreds.txt") | ForEach-Object {$_ -Replace "AzureUserNameValue", "$azureUsername"} | Set-Content -Path "C:\LabFiles\AzureCreds.txt"
  (Get-Content -Path "C:\LabFiles\AzureCreds.txt") | ForEach-Object {$_ -Replace "AzurePasswordValue", "$azurePassword"} | Set-Content -Path "C:\LabFiles\AzureCreds.txt"
  (Get-Content -Path "C:\LabFiles\AzureCreds.txt") | ForEach-Object {$_ -Replace "AzureSQLPasswordValue", "$azurePassword"} | Set-Content -Path "C:\LabFiles\AzureCreds.ps1"
  (Get-Content -Path "C:\LabFiles\AzureCreds.txt") | ForEach-Object {$_ -Replace "AzureTenantIDValue", "$azureTenantID"} | Set-Content -Path "C:\LabFiles\AzureCreds.txt"
  (Get-Content -Path "C:\LabFiles\AzureCreds.txt") | ForEach-Object {$_ -Replace "AzureSubscriptionIDValue", "$azureSubscriptionID"} | Set-Content -Path "C:\LabFiles\AzureCreds.txt"
  (Get-Content -Path "C:\LabFiles\AzureCreds.txt") | ForEach-Object {$_ -Replace "DeploymentIDValue", "$deploymentId"} | Set-Content -Path "C:\LabFiles\AzureCreds.txt"               
  (Get-Content -Path "C:\LabFiles\AzureCreds.txt") | ForEach-Object {$_ -Replace "ODLIDValue", "$odlId"} | Set-Content -Path "C:\LabFiles\AzureCreds.txt"  
  (Get-Content -Path "C:\LabFiles\AzureCreds.ps1") | ForEach-Object {$_ -Replace "ClientIdValue", ""} | Set-Content -Path "C:\LabFiles\AzureCreds.ps1"
  (Get-Content -Path "C:\LabFiles\AzureCreds.ps1") | ForEach-Object {$_ -Replace "AzureUserNameValue", "$azureUsername"} | Set-Content -Path "C:\LabFiles\AzureCreds.ps1"
  (Get-Content -Path "C:\LabFiles\AzureCreds.ps1") | ForEach-Object {$_ -Replace "AzurePasswordValue", "$azurePassword"} | Set-Content -Path "C:\LabFiles\AzureCreds.ps1"
  (Get-Content -Path "C:\LabFiles\AzureCreds.ps1") | ForEach-Object {$_ -Replace "AzureSQLPasswordValue", "$azurePassword"} | Set-Content -Path "C:\LabFiles\AzureCreds.ps1"
  (Get-Content -Path "C:\LabFiles\AzureCreds.ps1") | ForEach-Object {$_ -Replace "AzureTenantIDValue", "$azureTenantID"} | Set-Content -Path "C:\LabFiles\AzureCreds.ps1"
  (Get-Content -Path "C:\LabFiles\AzureCreds.ps1") | ForEach-Object {$_ -Replace "AzureSubscriptionIDValue", "$azureSubscriptionID"} | Set-Content -Path "C:\LabFiles\AzureCreds.ps1"
  (Get-Content -Path "C:\LabFiles\AzureCreds.ps1") | ForEach-Object {$_ -Replace "DeploymentIDValue", "$deploymentId"} | Set-Content -Path "C:\LabFiles\AzureCreds.ps1"
  (Get-Content -Path "C:\LabFiles\AzureCreds.ps1") | ForEach-Object {$_ -Replace "ODLIDValue", "$odlId"} | Set-Content -Path "C:\LabFiles\AzureCreds.ps1"
  Copy-Item "C:\LabFiles\AzureCreds.txt" -Destination "C:\Users\Public\Desktop"
}

Start-Transcript -Path C:\WindowsAzure\Logs\CloudLabsCustomScriptExtension.txt -Append

[Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls
[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls" 

mkdir "c:\temp" -ea SilentlyContinue;
mkdir "c:\labfiles" -ea SilentlyContinue;

#download the solliance pacakage
$WebClient = New-Object System.Net.WebClient;
$WebClient.DownloadFile("https://raw.githubusercontent.com/solliancenet/common-workshop/main/scripts/common.ps1","C:\LabFiles\common.ps1")
$WebClient.DownloadFile("https://raw.githubusercontent.com/solliancenet/common-workshop/main/scripts/httphelper.ps1","C:\LabFiles\httphelper.ps1")
$WebClient.DownloadFile("https://raw.githubusercontent.com/solliancenet/common-workshop/main/scripts/rundeployment.ps1","C:\LabFiles\rundeployment.ps1")

#run the solliance package
. C:\LabFiles\Common.ps1
. C:\LabFiles\HttpHelper.ps1

Set-Executionpolicy unrestricted -force

DisableInternetExplorerESC

EnableIEFileDownload

InstallChocolaty

InstallAzPowerShellModule

InstallChrome

InstallNotepadPP

#InstallDockerDesktop "wsuser"

InstallGit
       
InstallAzureCli

InstallOffice

Uninstall-AzureRm -ea SilentlyContinue

CreateLabFilesDirectory

$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine")

cd "c:\labfiles";

CreateCredFile $azureUsername $azurePassword $azureTenantID $azureSubscriptionID $deploymentId $odlId

. C:\LabFiles\AzureCreds.ps1

$userName = $AzureUserName                # READ FROM FILE
$password = $AzurePassword                # READ FROM FILE
$clientId = $TokenGeneratorClientId       # READ FROM FILE
$global:sqlPassword = $AzureSQLPassword          # READ FROM FILE

$securePassword = $password | ConvertTo-SecureString -AsPlainText -Force
$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $userName, $SecurePassword

Connect-AzAccount -Credential $cred | Out-Null

#make sure management groups are present...
StartTenantBackFill
 
# Template deployment
$rg = (Get-AzResourceGroup | Where-Object { $_.ResourceGroupName -like "*-security" });
$resourceGroupName = $rg.ResourceGroupName
$region = $rg.Location;
$deploymentId =  $rg.Tags["DeploymentId"]

$sub = Get-AzSubscription;

$subscriptionId = $sub.SubscriptionId;

$resourceName = "wssecurity$deploymentId";

$branchName = "main";
$workshopName = "sentinel-defender-workshop-400";
$repoUrl = "solliancenet/sentinel-defender-workshop-400";

#adding MS Defender exclude path...
Add-MpPreference -ExclusionPath "C:\labfiles"

#download the git repo...
Write-Host "Download Git repo." -ForegroundColor Green -Verbose
git clone https://github.com/solliancenet/$workshopName.git $workshopName

$templatesFile = "c:\labfiles\$workshopName\artifacts\environment-setup\automation\00-template.json"
$parametersFile = "c:\labfiles\$workshopName\artifacts\environment-setup\spektra\deploy.parameters.post.json"
$content = Get-Content -Path $parametersFile -raw;

$content = $content.Replace("GET-AZUSER-PASSWORD",$azurepassword);
$content = $content | ForEach-Object {$_ -Replace "GET-AZUSER-UPN", "$AzureUsername"};
$content = $content | ForEach-Object {$_ -Replace "GET-AZUSER-PASSWORD", "$AzurePassword"};
$content = $content | ForEach-Object {$_ -Replace "GET-ODL-ID", "$deploymentId"};
$content = $content | ForEach-Object {$_ -Replace "GET-DEPLOYMENT-ID", "$deploymentId"};
$content = $content | ForEach-Object {$_ -Replace "GET-REGION", $region};
$content = $content | ForEach-Object {$_ -Replace "ARTIFACTS-LOCATION", "https://raw.githubusercontent.com/$repoUrl/$branchName/artifacts/environment-setup/automation/"};
$content | Set-Content -Path "$($parametersFile).json";

#enable Microsoft defender for cloud on the subscription - do BEFORE deployment
EnableAzureDefender

#setup agent provisioning...
EnableASCAutoProvision $resourceName;

#enable the default policy
EnableDefaultASCPolicy

#enable the AKS policy
EnableAKSPolicy $resourceGroupName;

EnableOtherCompliancePolicy $resourceGroupName;

Write-Host "Assiging Permissions [Subscription]"

New-AzRoleAssignment -SignInName $username -RoleDefinitionName "Security Reader" -Scope "/subscriptions/$subscriptionId" -ErrorAction SilentlyContinue;
New-AzRoleAssignment -SignInName $username -RoleDefinitionName "Security Admin" -Scope "/subscriptions/$subscriptionId" -ErrorAction SilentlyContinue;

Write-Host "Assiging Permissions [Management Group]"

$mgmtGroup = Get-AzManagementGroup

New-AzRoleAssignment -SignInName $username -RoleDefinitionName "Security Reader" -Scope $mgmtGroup.Id -ErrorAction SilentlyContinue;
New-AzRoleAssignment -SignInName $username -RoleDefinitionName "Security Admin" -Scope $mgmtGroup.Id -ErrorAction SilentlyContinue;

Write-Host "Executing main ARM deployment" -ForegroundColor Green -Verbose

#OLD WAY...
#New-AzResourceGroupDeployment -ResourceGroupName $resourceGroupName -TemplateFile $templatesFile -TemplateParameterFile "$($parametersFile).json";

#will fire deployment async so the main deployment shows "succeeded"
ExecuteDeployment $templatesFile "$($parametersFile).json" $resourceGroupName;

#wait for storage to be created...
WaitForResource $resourceGroupName $resourceName "Microsoft.Storage/storageAccounts" 1000;

#connect the activity log - workspace must exist
ConnectAzureActivityLog $resourceName $resourceGroupName;

WaitForResource $resourceGroupName $resourceName "Microsoft.Sql/servers" 1000;

#upload the bacpac file...
$bacpacFilename = "Insurance.bacpac"

# The ip address range that you want to allow to access your server
$startip = "0.0.0.0";
$endip = "0.0.0.0";

cd "c:\labfiles\$workshopName\artifacts\environment-setup\automation";

$wsName = $resourceName;
$serverName = $resourceName;
$storageAccountName = $resourceName;

$dataLakeStorageBlobUrl = "https://"+ $wsName + ".blob.core.windows.net/"
$dataLakeStorageAccountKey = (Get-AzStorageAccountKey -ResourceGroupName $resourceGroupName -AccountName $wsName)[0].Value
$dataLakeContext = New-AzStorageContext -StorageAccountName $wsName -StorageAccountKey $dataLakeStorageAccountKey

$databaseName = "Insurance";

$storageContainerName = "sqlimport";
$sqlImportContainer = New-AzStorageContainer -Permission Container -name $storageContainerName -context $dataLakeContext;

Set-AzStorageBlobContent -Container $storagecontainername -File $bacpacFilename -Context $dataLakeContext

#create a database

#allow azure
$serverFirewallRule = New-AzSqlServerFirewallRule -ResourceGroupName $resourceGroupName -ServerName $serverName -AllowAllAzureIPs

#deploy the bacpac file...
$importRequest = New-AzSqlDatabaseImport -ResourceGroupName $resourceGroupName `
    -ServerName $serverName `
    -DatabaseName $databaseName `
    -DatabaseMaxSizeBytes 100GB `
    -StorageKeyType "StorageAccessKey" `
    -StorageKey $(Get-AzStorageAccountKey -ResourceGroupName $resourceGroupName -StorageAccountName $storageAccountName).Value[0] `
    -StorageUri "https://$storageaccountname.blob.core.windows.net/$storageContainerName/$bacpacFilename" `
    -Edition "Standard" `
    -ServiceObjectiveName "S3" `
    -AdministratorLogin "wsuser" `
    -AdministratorLoginPassword $(ConvertTo-SecureString -String $password -AsPlainText -Force)

#wait for database
WaitForResource $resourceGroupName $databaseName "Microsoft.Sql/servers/databases" 1000;

ExecuteSqlDatabaseScan $resourceName $databaseName;

#wait for log analytics to be created...
WaitForResource $resourceGroupName $resourceName "microsoft.operationalinsights/workspaces" 1000;

#DeployAllSolutions $resourceName $resourceGroupName;

#create a computer group
CreateSavedSearch $resourceName "all_computers" "Heartbeat | distinct Computer" "Groups" true;

#set log analytics config - not needed b/c autoprovisioning?
#SetLogAnalyticsAgentConfig $resourceName $resourceGroupName;

SetLogAnalyticsAgentConfigRest $resourceName $resourceGroupName;

#enable sql vulnerability
EnableSQLVulnerability $resourceName $resourceName $AzureUserName $resourceGroupName;

#enable vm vulnerability
EnableVMVulnerability;

WaitForResource $resourceGroupName "$resourcename-win10" "Microsoft.Compute/virtualMachines" 1000;

#enable JIT
#$excludeVms = @("$resourceName-win10");
#$excludeVms = @("labvm-$deploymentId");

EnableJIT $resourceGroupName $excludeVms;

#EnableJITRestApi $workshopName $excludeVms;

#turn on auto provision
SetDefenderAutoprovision $subscriptionId;

#set the workspace to the one we created not the ASC one.
SetDefenderWorkspace $resourceName $resourceGroupName $subscriptionId;

#enable continous export
EnableContinousExport $workshopName;

#create a saved search
CreateSavedSearch $resourceName "all_computers" "Heartbeat | distinct Computer" "Groups" true;

mkdir c:\logs -ea SilentlyContinue;

#remove AppLocker
Write-host "Removeing App Locker Policies";

$policy = Get-AppLockerPolicy -local
$policy.DeleteRuleCollections()

Stop-Transcript