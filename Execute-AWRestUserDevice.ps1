<# Execute-AWRestUserDevice Powershell Script Help

  .SYNOPSIS
    This Poweshell script make a REST API call to an AirWatch server.  This particular script is used to pull device information
    then based on the device record looks up the user.  Its primary purpose is to show the country the device is in based on an 
    AD custom attribute.  If you need to build your own script, concentrate on the Get-BasicUserForAuth function.  This creates 
    the Base64 authentication string.  Also look at the Build-Headers function as this is a requirement for the REST call.
    
  .DESCRIPTION
    To understand the underlying call check https://<your_AirWatch_Server>/API/v1/mdm/devices/help/resources/GetDevicesByBulkSerialNumber.
    It is always helpful to validate your parameter using something like the PostMan extension for Chrome
    https://chrome.google.com/webstore/detail/postman/fhbjgbiflinjbdggehcddcbncdddomop?hl=en

  .EXAMPLE
    Execute-AWRestUserDevice.ps1 -userName Administrator -password password -tenantAPIKey 4+apikeyw/krandomSstuffIleq4MY6A7WPmo9K9AbM6A= -outputFile c:\Users\Administrator\Desktop\output.txt -AirWatchURL https://cn135.awmdm.com -lastSeenDays 30-Verbose
  
  .PARAMETER userName
    An AirWatch account in the tenant is being queried.  This user must have the API role at a minimum.

  .PARAMETER password
    The password that is used by the user specified in the username parameter

  .PARAMETER tenantAPIKey
    This is the REST API key that is generated in the AirWatch Console.  You locate this key at All Settings -> Advanced -> API -> REST,
    and you will find the key in the API Key field.  If it is not there you may need override the settings and Enable API Access

  .PARAMETER airWatchURL
    This will be the https://<your_AirWatch_Server>, ex. https://cn135.awmdm.com.

  .PARAMETER outputFile
    This will be the file that contains the list of devices and users.
    
  .PARAMETER dayLastSeen (optional)
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
        [string]$outputFile,

        [Parameter(Mandatory=$True)]
        [string]$airWatchURL,

        [Parameter()]
        [string]$lastSeenDays
)

Write-Verbose "-- Command Line Parameters --"
Write-Verbose ("UserName: " + $userName)
Write-Verbose ("Password: " + $password)
Write-Verbose ("Tenant API Key: " + $tenantAPIKey)
Write-Verbose ("Endpoint URL: " + $airWatchURL)
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
  Because we are only looking for the devices that have been seen in a specific amount of time we need to build the time value to
  add it to the endpoint query.
#>
Function Get-DateLastSeen {
    
    Param([string]$daysToGoBack)
    if ([string]::IsNullOrEmpty($daysToGoBack)) {
        $daysToGoBack = 30
    }
    $dateToFormat = (Get-Date).AddDays(-$daysToGoBack)
    $dateSeenString = $dateToFormat.ToString("yyyy-MM-ddTHH:mm:ss.fff")
    $dateToPrint = $dateToFormat.ToString("yyyy-MM-ddTHH:mm:ss.fff")
    #Write-Output("Getting Device Last Seen Since: " + $dateToPrint)

    Return $dateSeenString
}

<#
  Pretty self explanatory.  Because we are creating a CSV file we need to provide a header.
#>
Function Build-OutputHeader {
 
    $headerOut = "UDID,SerialNumber,MacAddress,IMEI,AssetNumber,DeviceFriendlyName,LocationGroupName,UserName,UserEmailAddress,Ownership,Platform,"
    $headerOut = $headerOut + "Model,OperatingSystem,PhoneNumber,LastSeen,EnrollmentStatus,ComplianceStatus,CompromisedStatus,LastEnrolledOn,"
    $headerOut = $headerOut + "LastComplianceCheckOn,LastCompromisedCheckOn,IsSupervised,AcLineStatus,VirtualMemory,AirWatchUserID,UserCountry"

    Out-File -FilePath $outputFile -InputObject $headerOut
}

<#
  This function is required to pull the Custom User Attribute for the user that owns the device.  It is then returned to the
  Parse-DeviceObject 
#>
Function Get-UserAttributes {
    
    param([String]$userIDAttrib, [String]$airWatchServer, [Hashtable]$userHeaders)

    $userEndPointURL = "/api/system/users/" + $userIDAttrib
    $completeURL = $airWatchServer + $userEndPointURL
    
    $userResult = Invoke-RestMethod -Method GET -Uri $completeURL -Headers $userHeaders
    Return $userResult.CustomAttribute1
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
    $airWatchUserID = $device.UserID.Id.Value
}

$concateUserInfo = $userName + ":" + $password
$deviceListURI = $baseURL + $bulkDeviceEndpoint
$restUserName = Get-BasicUserForAuth($concateUserInfo)

<#
  Build the headers and send the request to the server.  The response is returned as a PSObject $webReturn, which is a collection
  of the devices.  Parse-DeviceObject gets all of the device properties.  This example also prints out the AirWatch device ID, 
  friendly name, and user name
#>
$deviceSearchEndpoint = "/api/mdm/devices/search?seensince="
$dateLastSeenValue = Get-DateLastSeen $daysLastSeen
$endpointURL = $airWatchURL + $deviceSearchEndpoint + $dateLastSeenValue

$useJSON = "application/json"
$headers = Build-Headers $restUserName $tenantAPIKey $useJSON $useJSON
$webReturn = Invoke-RestMethod -Method GET -Uri $endpointURL -Headers $headers -Body $deviceListJSON

Build-OutputHeader
foreach ($currentDevice in $webReturn.Devices) {
	Parse-DeviceObject($currentDevice)
    $userIDString = [string]$currentDevice.UserID.ID.Value

    $userCountry = Get-UserAttributes $userIDString  $airWatchURL  $headers
	$outputLine = [String]$currentDevice.Id.Value + [char]9 + $currentDevice.DeviceFriendlyName + [char]9 + $currentDevice.UserName + [char]9 + $userCountry
	$outputLine = $outputLine + [char]9 + $currentDevice.LastSeen
	Write-Output $outputLine

    $printLine = [String]$currentDevice.Id.Value + "," + $currentDevice.SerialNumber + "," + $currentDevice.MacAddress + "," + $currentDevice.Imei + ","
    $printLine = $printLine + $currentDevice.AssetNumber + "," + $currentDevice.DeviceFriendlyName + "," + $currentDevice.LocationGroupName + ","
    $printLine = $printLine + $currentDevice.UserName + "," + $currentDevice.UserEmailAddress + "," + $currentDevice.Ownership + "," + $currentDevice.PlatformID.Name + ","
    $printLine = $printLine + $currentDevice.Model + "," + $currentDevice.OperatingSystem + "," + $currentDevice.PhoneNumber + "," + $currentDevice.LastSeen + ","
    $printLine = $printLine + $currentDevice.EnrollmentStatus + "," + $currentDevice.ComplianceStatus + "," + $currentDevice.CompromisedStatus + ","
    $printLine = $printLine + $currentDevice.LastEnrolledOn + "," + $currentDevice.LastComplianceCheckOn + "," + $currentDevice.LastCompromisedCheckOn + ","
    $printLine = $printLine + $currentDevice.IsSupervised + "," + $currentDevice.AcLineStatus + "," + $currentDevice.VirtualMemory + "," + [String]$currentDevice.Id.Value + ","
    $printLine = $printLine + $userCountry

    Out-File -FilePath $outputFile -Append -InputObject $printLine
}
