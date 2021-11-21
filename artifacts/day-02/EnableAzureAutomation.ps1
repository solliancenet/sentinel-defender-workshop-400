. C:\LabFiles\Common.ps1

Login-AzureCredsPowerShell

Set-AzOperationalInsightsIntelligencePack -ResourceGroupName "#RESOURCE_GROUP_NAME#" -WorkspaceName "#WORKSPACE_NAME#" -IntelligencePackName "AzureAutomation" -Enabled $true