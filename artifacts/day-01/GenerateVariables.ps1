$context = Get-AzContext

$username = $context.Account.id;

$path = "c:\temp\tokens\$username";
mkdir $path -ea SilentlyContinue;
$filePath = "$path\variables.csv";
remove-item $filepath -ea SilentlyContinue;

$line = "SubscriptionId,TenantId,WorkspaceId"
add-content "$filePath" $line

$rg = (Get-AzResourceGroup | Where-Object { $_.ResourceGroupName -like "*-security" });
$resourceGroupName = $rg.ResourceGroupName
$deploymentId =  $rg.Tags["DeploymentId"]
$resourceName = "wssecurity$deploymentId";

$ws = Get-AzOperationalInsightsWorkspace -name $resourceName -ResourceGroupName $resourceGroupName

$line = "$($context.Subscription.Id),$($context.Tenant.Id),$($ws.customerId)"
add-content "$filePath" $line