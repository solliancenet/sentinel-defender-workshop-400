function CreateMacro($file)
{
    $encoded = EncodeScript $file;

    $cmd = "strCommand = `"powershell.exe -encodedCommand $encoded`"";

    return $cmd;
}

function CreateEncodedCommand($file)
{
    $encoded = EncodeScript $file;

    $cmd = "`"powershell.exe -encodedCommand $encoded`"";

    return $cmd;
}

function EncodeScript($file)
{
    $raw = get-content $file -raw;
    $encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($raw));
    return $encoded;
}

$path = "C:\github\solliancenet\sentinel-defender-workshop-400\artifacts\day-02";

$file = "$path\Enumerate.ps1";

$cmd = EncodeScript $file;

$file = "$path\Obfuscate.ps1";

CreateEncodedCommand $file;

#$cmd = CreateMacro $file;

#$cmd;