
<# Execute-AWRestAPI Powershell Script Help

  .SYNOPSIS
    This Poweshell script make a REST API call to an AirWatch server.  This particular script is used to pull device information
    based on serial numbers pulled from a file.  If you need to build your own script, concentrate on the Get-BasicUserForAuth
    function.  This creates the Base64 authentication string.  Also look at the Build-Headers function as this is a requirement 
    for the REST call.
    
  .DESCRIPTION
    To understand the underlying call check https://<your_AirWatch_Server>/API/v1/mdm/devices/help/resources/GetDevicesByBulkSerialNumber.
    It is always helpful to validate your parameter using something like the PostMan extension for Chrome
    https://chrome.google.com/webstore/detail/postman/fhbjgbiflinjbdggehcddcbncdddomop?hl=en

  .EXAMPLE
    Execute-AWRestAPI.ps1 -userName Administrator -password password -tenantAPIKey 4+apikeyw/krandomSstuffIleq4MY6A7WPmo9K9AbM6A= -outputFile c:\Users\Administrator\Desktop\output.txt -endpointURL https://demo/awmdm.com/API/v1/mdm/devices/serialnumber  -inputFile C:\Users\Administrator\Desktop\SerialNumbers1.txt -Verbose
  
  .PARAMETER userName
    An AirWatch account in the tenant is being queried.  This user must have the API role at a minimum.

  .PARAMETER password
    The password that is used by the user specified in the username parameter

  .PARAMETER tenantAPIKey
    This is the REST API key that is generated in the AirWatch Console.  You locate this key at All Settings -> Advanced -> API -> REST,
    and you will find the key in the API Key field.  If it is not there you may need override the settings and Enable API Access

  .PARAMETER endpointURL
    This will be the https://<your_AirWatch_Server>/API/v1/mdm/devices/serialnumber.  If you want to modify this script to get other data
    please contact the REST API help at https://<your_AirWatch_Server>/API/help.

  .PARAMETER inputFile
    This will be the complete path and filename to a file that list you device serial numbers.  You will have one serial number per line
    with not fomatting.  Just the serial number of the device(s) you want information for.

  .PARAMETER outputFile (optional)
    This is not required.  If you don't specify this parameter on the command line, the script will just show
    
#>

[CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$userName,

        [Parameter(Mandatory=$True)]
        [string]$password,

        [Parameter(Mandatory=$True)]
        [string]$tenantAPIKey,

        [Parameter(Mandatory=$True)]
        [string]$endpointURL,

        [Parameter(Mandatory=$True)]
        [string]$inputFile,

        [Parameter()]
        [string]$outputFile
)

Write-Verbose "-- Command Line Parameters --"
Write-Verbose ("UserName: " + $userName)
Write-Verbose ("Password: " + $password)
Write-Verbose ("Tenant API Key: " + $tenantAPIKey)
Write-Verbose ("Endpoint URL: " + $endpointURL)
Write-Verbose ("Input File: " + $inputFile)
Write-Verbose ("Output File: " + $outputFile)
Write-Verbose "-----------------------------"
Write-Verbose ""

<#
  This implementation uses Baisc authentication.  See "Client side" at https://en.wikipedia.org/wiki/Basic_access_authentication for a description
  of this implementation.
#>
Function Get-BasicUserForAuth {

	Param([string]$func_username)

	$userNameWithPassword = $func_username
	$encoding = [System.Text.Encoding]::ASCII.GetBytes($userNameWithPassword)
	$encodedString = [Convert]::ToBase64String($encoding)

	Return "Basic " + $encodedString
}

Function Build-Headers {

    Param([string]$authoriztionString, [string]$tenantCode, [string]$acceptType, [string]$contentType)

    $authString = $authoriztionString
    $tcode = $tenantCode
    $accept = $acceptType
    $content = $contentType

    Write-Verbose("---------- Headers ----------")
    Write-Verbose("Authorization: " + $authString)
    Write-Verbose("aw-tenant-code:" + $tcode)
    Write-Verbose("Accept: " + $accept)
    Write-Verbose("Content-Type: " + $content)
    Write-Verbose("------------------------------")
    Write-Verbose("")
    $header = @{"Authorization" = $authString; "aw-tenant-code" = $tcode; "Accept" = $useJSON; "Content-Type" = $useJSON}
     
    Return $header
}

<#
  To get return a large number of devices you send a list of serial numbers (see documentation for other fields) to the REST endpoint.
  It will be in this section that you add code to build the list of devices that you want returned.  This example hard codes a two device
  list in the $serialNumber variable.  Modify the code to populate this array for your devices.
#>
Function Set-DeviceListJSON {

	param([array]$serialNumbers)

	# $serialNumbers = @("DLXNV3RZFLMJ", "d3a2319f")
	$quoteCharacter = [char]34
	$bulkRequestObject = "{ " + $quoteCharacter + "BulkValues" + $quoteCharacter + ":{ " + $quoteCharacter + "Value" + $quoteCharacter + ": ["
	foreach ($serialNumber in $serialNumbers) {
		$bulkRequestObject = $bulkRequestObject + $quoteCharacter + $serialNumber + $quoteCharacter + ", "
	}
	[int]$stringLength = $bulkRequestObject.Length
	[int]$lengthToLastComma = $stringLength - 2
	$bulkRequestObject = $bulkRequestObject.Substring(0, $lengthToLastComma)
	$bulkRequestObject = $bulkRequestObject + " ] }}"
	
    Write-Verbose "------- JSON to Post---------"
    Write-Verbose $bulkRequestObject
    Write-Verbose "-----------------------------"
    Write-Verbose ""
	Return $bulkRequestObject
}

<#
  This is a function based on https://www.uvm.edu/~gcd/2010/11/powershell-join-string-function/.  What it does is take an array of all
  of the device fields and create a comma separated line of data for output.
#>
Function Get-StringFromArray {

    Param([string[]]$deviceFields, [string]$separator = ",")

    $first = $True
    foreach ($currentField in $deviceFields) {
        If ($first -eq $True) {
            $outputString = $currentField
            $first = $false
        } Else {
            $outputString = $separator + $currentField
        }
    }
    
    Return $outputString
}

Function Build-OutputHeader {
    
    $devElements = @()
    $devElements += "UDID" > $null
    $devElements += "SerialNumber" > $null
    $devElements += "MacAddress"
    $devElements += "Imei"
    $devElements += "AssetNumber"
    $devElements += "DeviceFriendlyName"
    $devElements += "LocationGroupName"
    $devElements += "UserName"
    $devElements += "UserEmailAddress"
    $devElements += "Ownership"
    $devElements += "Platform"
    $devElements += "Model"
    $devElements += "OperatingSystem"
    $devElements += "PhoneNumber"
    $devElements += "LastSeen"
    $devElements += "EnrollmentStatus"
    $devElements += "ComplianceStatus"
    $devElements += "CompromisedStatus"
    $devElements += "LastEnrolledOn"
    $devElements += "LastComplianceCheckOn"
    $devElements += "LastCompromisedCheckOn"
    $devElements += "IsSupervised"
    $devElements += "DataEncryptionYN"
    $devElements += "AcLineStatus"
    $devElements += "VirtualMemory"
    $devElements += "OEMInfo"
    $devElements += "AirWatchID"
    Write-Output $devElements.Count
    Return $devElements
}

<#
  This is nothing more than a helper function to pull all of the device properties.  Probably just used to get the syntax.  Send in
  a device object.
#>
Function Parse-DeviceObject {
	param([PSObject]$device)

	# Uncomment the following line to see the properties for a device
	# Write-Output Get-Member $device

	$udid = $device.Udid
	$serialNumber = $device.SerialNumber
	$macAddress = $device.MacAddress
	$iemi = $device.Imei
	$assetNumber = $device.AssetNumber
	$deviceFriendlyName = $device.DeviceFriendlyName
	$locationGroupName = $device.LocationGroupName
	$userName = $device.UserName
	$userEmailAddress = $device.UserEmailAddress
	$ownership = $device.Ownership
	$platform = $device.PlatformId.Name
	$model = $device.Model
	$osVersion = $device.OperatingSystem
	$phoneNumber = $device.PhoneNumber
	$lastSeen = $device.LastSeen
	$enrollmentStatus = $device.EnrollmentStatus
	$complianceStatus = $device.ComplianceStatus
	$compromiseStatus = $device.CompromisedStatus
	$lastEnrolled = $device.LastEnrolledOn
	$lastComplianceCheck = $device.LastComplianceCheckOn
	$lastCompromisedCheck = $device.LastCompromisedCheckOn
	$isSupervised = $device.IsSupervised
	$dataEncryption = $device.DataEncryptionYN
	$acLine = $device.AcLineStatus
	$virtualMemory = $device.VirtualMemory
	$oemInfo = $device.OEMInfo
	$airWatchID = $device.Id.Value
}


$concateUserInfo = $userName + ":" + $password
$deviceListURI = $baseURL + $bulkDeviceEndpoint
$restUserName = Get-BasicUserForAuth ($concateUserInfo)

If (Test-Path $inputFile) {
    $serialNumberList = Get-Content($inputFile)
    $deviceListJSON = Set-DeviceListJSON($serialNumberList)
} Else {
    Write-Host ("File: " + $inputFile + " not found.")
}

<#
  Build the headers and send the request to the server.  The response is returned as a PSObject $webReturn, which is a collection
  of the devices.  Parse-DeviceObject gets all of the device properties.  This example also prints out the AirWatch device ID, 
  friendly name, and user name
#>
$useJSON = "application/json"
$headers = Build-Headers $restUserName $tenantAPIKey $useJSON $useJSON
$webReturn = Invoke-RestMethod -Method Post -Uri $endpointURL -Headers $headers -Body $deviceListJSON

foreach ($currentDevice in $webReturn.Devices) {
    Build-OutputHeader
	Parse-DeviceObject($currentDevice)
	$outputLine = [String]$currentDevice.Id.Value + [char]9 + $currentDevice.DeviceFriendlyName + [char]9 + $currentDevice.UserName
	$outputLine = $outputLine + [char]9 + $currentDevice.LastSeen
	Write-Output $outputLine
}
