$subscriptionId = "#SUBSCRIPTION_ID#";
$resourceGroupName = "#RESOURCE_GROUP_NAME#";
$workspaceName = "#WORKSPACE_NAME#";
$storageAccountName = "#STORAGE_ACCOUNT_NAME#";
$exportName = "ExportStorageAccount";

$url = "https://management.azure.com/subscriptions/$subscriptionId/resourcegroups/$resourceGroupName/providers/Microsoft.operationalInsights/workspaces/$workspaceName/dataexports/$($exportName)?api-version=2020-08-01";

cd "c:/labfiles/#WORKSHOP_NAME#/artifacts/day-01";

$post = get-content "storage_post.json";

#$post = $post.replace("#SUBSCRIPTION_ID#",$subscriptionId);
#$post = $post.replace("#RESOURCE_GROUP_NAME#",$resourceGroupName);
#$post = $post.replace("#WORKSPACE_NAME#",$workspaceName);
#$post = $post.replace("#STORAGE_ACCOUNT_NAME#",$storageAccountName);

. C:\LabFiles\Common.ps1

Login-AzureCredsPowerShell

$azToken = Get-AzAccessToken -ResourceUrl "https://management.azure.com";

tokenValue = $azToken.Token;

#do the post...
$headers = @{
    'Authorization' = "Bearer " + $tokenValue;
    'Content-Type' = "application/json";
}

$res = Invoke-RestMethod -Uri $url -Method PUT -Headers $headers -Body $post

$res;

#reference - https://docs.microsoft.com/en-us/azure/azure-monitor/logs/logs-data-export?tabs=rest