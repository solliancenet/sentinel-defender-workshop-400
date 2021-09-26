function GetToken()
{
  . C:\LabFiles\AzureCreds.ps1

  $userName = $AzureUserName                # READ FROM FILE
  $password = $AzurePassword                # READ FROM FILE
  $clientId = $TokenGeneratorClientId       # READ FROM FILE
  $global:sqlPassword = $AzureSQLPassword          # READ FROM FILE

  $securePassword = $password | ConvertTo-SecureString -AsPlainText -Force
  $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $userName, $SecurePassword

  Connect-AzAccount -Credential $cred | Out-Null

  #$clientId = "1b730954-1685-4b74-9bfd-dac224a7b894";
  $clientId = "1b730954-1685-4b74-9bfd-dac224a7b894";
  #$clientId = "01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9";
  $clientId = "de0853a1-ab20-47bd-990b-71ad5077ac7b";

  $subscriptionId = (Get-AzContext).Subscription.Id
  $tenantId = (Get-AzContext).Tenant.Id;
  $global:logindomain = (Get-AzContext).Tenant.Id;

  $resource = "urn:ms-drs:enterpriseregistration.windows.net";

  $ropcBodyCore = "client_id=$($clientId)&username=$($userName)&password=$($password)&grant_type=password"
  $global:ropcBodySynapse = "$($ropcBodyCore)&scope=$resource"

  $redirectUrl = "https://portal.azure.com/TokenAuthorize";

  $url = "https://login.microsoftonline.com/$($global:logindomain)/oauth2/authorize?client_id=$clientId&response_type=code&redirect_uri=$redirectUrl&nonce=1234&resource=$resource&prompt=admin_consent";

  $url = "https://login.microsoftonline.com/$($global:logindomain)/adminConsent?client_id=$clientId&redirect_uri=https://portal.azure.com/TokenAuthorize";

  $url = "https://login.microsoftonline.com/$($global:logindomain)/adminConsent?client_id=$clientId";

  #$url = "https://login.microsoftonline.com/common/oauth2/authorize?client_id=$clientId&response_type=code"

  start-process $url;

  $result = Invoke-RestMethod  -Uri "https://login.microsoftonline.com/$($global:logindomain)/oauth2/v2.0/token" -Method POST -Body $global:ropcBodySynapse -ContentType "application/x-www-form-urlencoded"

  $global:aaDToken = $result.access_token

  $PackageId = [Guid]::NewGuid();
  $Expires=(Get-Date).AddMonths(1)

  if([string]::IsNullOrEmpty($Name))
  {
      $Name = "package_$($PackageId.ToString())"
  }

  $body = @{
      "pid" =  $PackageId.ToString()
      "name" = $Name
      "exp" =  $Expires.ToString("MM/dd/yyyy")
  }

  # Make the first request to get flowToken
  $response = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/webapp/bulkaadjtoken/begin" -Headers $headers -Body ($body | ConvertTo-Json) -ContentType "application/json; charset=utf-8"

  if($response.state -like "*Error*")
  {
      $resultData = $response.resultData | ConvertFrom-Json
      throw $resultData.error_description
  }

  # Get the BPRT
  $response = Invoke-RestMethod -UseBasicParsing -Method Get -Uri "https://login.microsoftonline.com/webapp/bulkaadjtoken/poll?flowToken=$($response.flowToken)" -Headers $headers

  $details = $response.resultData | ConvertFrom-Json
}

# Install the module
Install-Module AADInternals

# Import the module
Import-Module AADInternals

#install the ICD tool...
#TODO

#gotta authorize the WCD tool
#TODO

#get an azure ad token with refresh token...
#TODO

#https://o365blog.com/post/bprt/
#get a bulk update token...

$url = "https://login.microsoftonline.com/webapp/bulkaadjtoken/begin"

$post = @{
  "pid" =  $PackageId.ToString()
  "name" = $Name
  "exp" =  $Expires.ToString("MM/dd/yyyy")
}

# Get the access token
Get-AADIntAccessTokenForAADGraph -Resource urn:ms-drs:enterpriseregistration.windows.net -SaveToCache

# Create a new BPRT
$bprt = New-AADIntBulkPRTToken -Name "My BPRT user"

Get-AADIntAccessTokenForAADJoin -BPRT $BPRT -SaveToCache

Join-AADIntDeviceToAzureAD -DeviceName "My computer"

#intune

Get-AADIntAccessTokenForIntuneMDM -BPRT $BPRT -PfxFileName .\d03994c9-24f8-41ba-a156-1805998d6dc7.pfx -SaveToCache

#join to intune
Join-AADIntDeviceToIntune -DeviceName "My computer"

$toolPath = "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Imaging and Configuration Designer\x86"

cd $toolPath;

$path = "C:\temp\project_3";

#https://docs.microsoft.com/en-us/windows/configuration/provisioning-packages/provisioning-command-line
icd.exe /Build-ProvisioningPackage /CustomizationXML:"$path/customizations.xml" /PackagePath:"$path/BulkJoin.ppkg" +overwrite

#https://thewindowsupdate.com/2021/05/26/bulk-join-a-windows-device-to-azure-ad-and-microsoft-endpoint-manager-using-a-provisioning-package/
#https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/dism-provisioning-package-command-line-options
DISM.exe /online /Add-ProvisioningPackage /PackagePath:"$path/BulkJoin.ppkg"

. C:\LabFiles\AzureCreds.ps1

$userName = $AzureUserName                # READ FROM FILE
$password = $AzurePassword                # READ FROM FILE
$clientId = $TokenGeneratorClientId       # READ FROM FILE
$global:sqlPassword = $AzureSQLPassword          # READ FROM FILE

$securePassword = $password | ConvertTo-SecureString -AsPlainText -Force
$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $userName, $SecurePassword

Connect-AzAccount -Credential $cred | Out-Null

$subscriptionId = (Get-AzContext).Subscription.Id
$tenantId = (Get-AzContext).Tenant.Id;
$global:logindomain = (Get-AzContext).Tenant.Id;

$ropcBodyCore = "client_id=$($clientId)&username=$($userName)&password=$($password)&grant_type=password"
$global:ropcBodySynapse = "$($ropcBodyCore)&scope=urn:ms-drs:enterpriseregistration.windows.net"

$result = Invoke-RestMethod  -Uri "https://login.microsoftonline.com/$($global:logindomain)/oauth2/v2.0/token" -Method POST -Body $global:ropcBodySynapse -ContentType "application/x-www-form-urlencoded"

$global:aaDToken = $result.access_token

$PackageId = [Guid]::NewGuid();
$Expires=(Get-Date).AddMonths(1)

if([string]::IsNullOrEmpty($Name))
{
    $Name = "package_$($PackageId.ToString())"
}

$body = @{
    "pid" =  $PackageId.ToString()
    "name" = $Name
    "exp" =  $Expires.ToString("MM/dd/yyyy")
}

# Make the first request to get flowToken
$response = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/webapp/bulkaadjtoken/begin" -Headers $headers -Body ($body | ConvertTo-Json) -ContentType "application/json; charset=utf-8"

if($response.state -like "*Error*")
{
    $resultData = $response.resultData | ConvertFrom-Json
    throw $resultData.error_description
}

# Get the BPRT
$response = Invoke-RestMethod -UseBasicParsing -Method Get -Uri "https://login.microsoftonline.com/webapp/bulkaadjtoken/poll?flowToken=$($response.flowToken)" -Headers $headers

$details = $response.resultData | ConvertFrom-Json