<#
  The following variables are unique to each environment.
	$userName = The AirWatch Administrator account with at least the API Role
	$password = The password for the userName
	$tenantAPIKey = The REST API key for the AirWatch tenant you are accessing.  All Settings -> System -> Advanced -> API -> REST (API Key)
	$baseURL = The URL to your AirWatch Instance.
	$bulkDeviceEndpoint = The Resource URL for your query.  These can be found in the REST API Guide in the MyAirWatch portal.
	$serialNumberFile = The path to the file that contains the serial numbers you want to query.
#>
$userName = 
$password = 
$tenantAPIKey = 
$useJSON = "application/json"
$baseURL = "https://demo.awmdm.com"
$bulkDeviceEndpoint = "/API/v1/mdm/devices/serialnumber"
$serialNumberFile = $env:USERPROFILE + "\Desktop\SerialNumbers.txt"

<#
  This implementation uses Baisc authentication.  See "Client side" at https://en.wikipedia.org/wiki/Basic_access_authentication for a description
  of this implementation.
#>
Function Get-BasicUserForAuth {

	param([string]$func_username)

	$userNameWithPassword = $func_username
	$encoding = [System.Text.Encoding]::ASCII.GetBytes($userNameWithPassword)
	$encodedString = [Convert]::ToBase64String($encoding)

	Return "Basic " + $encodedString
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
	
	Return $bulkRequestObject
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

<#
  Build the basic authentication field, URI, and the device list JSON file for the POST request
#>
$concateUserInfo = $userName + ":" + $password
$deviceListURI = $baseURL + $bulkDeviceEndpoint
$restUserName = Get-BasicUserForAuth ($concateUserInfo)

If (Test-Path $serialNumberFile) {
	$fileList = Get-Content $serialNumberFile
	$deviceListJSON = Set-DeviceListJSON($fileList)
}

<#
  Build the headers and send the request to the server.  The response is returned as a PSObject $webReturn, which is a collection
  of the devices.  Parse-DeviceObject gets all of the device properties.  This example also prints out the AirWatch device ID, 
  friendly name, and user name
#>
$headers = @{"Authorization" = $restUserName; "aw-tenant-code" = $tenantAPIKey; "Accept" = $useJSON; "Content-Type" = $useJSON}
$webReturn = Invoke-RestMethod -Method Post -Uri $deviceListURI -Headers $headers -Body $deviceListJSON

foreach ($currentDevice in $webReturn.Devices) {
	Parse-DeviceObject($currentDevice)
	$outputLine = [String]$currentDevice.Id.Value + [char]9 + $currentDevice.DeviceFriendlyName + [char]9 + $currentDevice.UserName
	$outputLine = $outputLine + [char]9 + $currentDevice.LastSeen
	Write-Output $outputLine
}
