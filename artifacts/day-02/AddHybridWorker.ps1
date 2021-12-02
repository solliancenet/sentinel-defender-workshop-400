. C:\LabFiles\Common.ps1

Login-AzureCredsPowerShell

$item = Get-ChildItem -Path "C:\Program Files\Microsoft Monitoring Agent\Agent\AzureAutomation" -Include *Registration.psd1 -File -Recurse -ErrorAction SilentlyContinue

cd $item.PSParentPath;

Import-Module .\HybridRegistration.psd1

$groupName = "onpremises-win-group";
$url = "#AUTOMATION_URL#";
$key = "#AUTOMATION_KEY#";

Add-HybridRunbookWorker -GroupName $groupName -Url $url -Key $key;