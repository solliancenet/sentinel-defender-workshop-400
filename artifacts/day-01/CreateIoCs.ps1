$subscriptionId = "#SUBSCRIPTION_ID#";
$resourceGroupName = "#RESOURCE_GROUP_NAME#";
$workspaceName = "#WORKSPACE_NAME#";

$id = [Guid]::NewGuid();

$url = "https://management.azure.com/subscriptions/$subscriptionId/resourcegroups/$resourceGroupName/providers/Microsoft.operationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/threatintelligence/main/createIndicator?api-version=2019-01-01-preview";

cd "c:/labfiles/#WORKSHOP_NAME#/artifacts/day-01"

. C:\LabFiles\Common.ps1

Login-AzureCredsPowerShell

$azToken = Get-AzAccessToken -ResourceUrl "https://management.azure.com";

#get an access token...
$tokenValue = $azToken.Token;

$ips = @("#IP_1#","#IP_2#","#IP_3#");

foreach($ip in $ips)
{
    $post = get-content "iocTemplate.json";

    <#
    $post = $post.replace("#SUBSCRIPTION_ID#",$subscriptionId);
    $post = $post.replace("#RESOURCE_GROUP_NAME#",$resourceGroupName);
    $post = $post.replace("#WORKSPACE_NAME#",$workspaceName);
    #>
    
    $post = $post.replace("#NAME#",$ip);
    $post = $post.replace("#DESCRIPTION#",$ip);
    $post = $post.replace("#CREATED#", "Mon, 22 Nov 2021 08:00:00 GMT");
    $post = $post.replace("#IP_ADDRESS#",$ip);

    #do the post...
    $headers = @{
        'Authorization' = "Bearer " + $tokenValue;
        'Content-Type' = "application/json";
    }

    $res = Invoke-RestMethod -Uri $url -Method POST -Headers $headers -Body $post

}