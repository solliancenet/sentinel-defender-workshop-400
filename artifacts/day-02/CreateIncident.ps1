$subscriptionId = "#SUBSCRIPTION_ID#";
$resourceGroupName = "#RESOURCE_GROUP_NAME#";
$workspaceName = "#WORKSPACE_NAME#";

$id = [Guid]::NewGuid();

$url = "https://management.azure.com/subscriptions/$subscriptionId/resourcegroups/$resourceGroupName/providers/Microsoft.operationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/incidents/$($id)?api-version=2021-04-01";

cd "c:/labfiles/#WORKSHOP_NAME#/artifacts/day-02"

$post = get-content "incident_post.json";

$post = $post.replace("#SUBSCRIPTION_ID#",$subscriptionId);
$post = $post.replace("#RESOURCE_GROUP_NAME#",$resourceGroupName);
$post = $post.replace("#WORKSPACE_NAME#",$workspaceName);

. C:\LabFiles\Common.ps1

Login-AzureCredsPowerShell

$azToken = Get-AzAccessToken -ResourceUrl "https://management.azure.com";

#get an access token...
$tokenValue = $azToken.Token;

#do the post...
$headers = @{
    'Authorization' = "Bearer " + $tokenValue;
    'Content-Type' = "application/json";
}

$res = Invoke-RestMethod -Uri $url -Method PUT -Headers $headers -Body $post

$res;

#reference - https://docs.microsoft.com/en-us/rest/api/securityinsights/incidents/create-or-update