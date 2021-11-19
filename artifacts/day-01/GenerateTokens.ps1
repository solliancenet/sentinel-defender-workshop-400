function GetToken($res)
{
    $item = Get-AzAccessToken -ResourceUrl $res;

    $clientId = "1950a258-227b-4e31-a9cf-717495945fc2";

    $line = "$($item.Tenantid),$ClientId,$res,$($item.RefreshToken),$($item.Token),$($item.ExpiresOn)" 

    return $line;
}

$tokens = @();

$context = Get-AzContext

$username = $context.Account.id;

$path = "c:\temp\tokens\$username";
mkdir $path -ea SilentlyContinue;
$filePath = "$path\tokens.csv";
remove-item $filepath -ea SilentlyContinue;

$line = "TenantId,ClientId,Resource,RefreshToken,AccessToken,ExpiresOn"
add-content "$filePath" $line

$resources = @("https://management.azure.com", "https://api.loganalytics.io", "https://graph.microsoft.com", "https://graph.windows.net", "74658136-14ec-4630-ad9b-26e160ff0fc6", "https://app.vssps.visualstudio.com", "https://outlook.office365.com");

foreach ($res in $resources)
{
    $line = GetToken $res
    add-content "$filePath" $line
}