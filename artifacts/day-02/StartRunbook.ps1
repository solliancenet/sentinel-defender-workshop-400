. C:\LabFiles\Common.ps1

Login-AzureCredsPowerShell

Start-AzAutomationRunbook -ResourceGroupName "#RESOURCE_GROUP_NAME#" -AutomationAccountName "#WORKSPACE_NAME#" -Name "Reboot" -RunOn "onpremises-win-group"