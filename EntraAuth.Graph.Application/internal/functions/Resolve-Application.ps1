function Resolve-Application {
	<#
	.SYNOPSIS
		Returns the App Registration object identified by the provided identifier.
	
	.DESCRIPTION
		Returns the App Registration object identified by the provided identifier.
		This is an internal extension of the Get-EAGAppRegistration command,
		enabling caching of results for repeated resolutions of the same identifiers
		during a single instance of the calling command.

		Hence this helper can be called repeatedly from the same caller and it will
		resolve the same App Registration only once.

		This command always returns an obbject with the following properties:
		- Success: A boolean indicating if the resolution was successful.
		- Result: The resolved App Registration object(s).
		- Message: A message indicating the result of the resolution.
		The caller is responsible for handling error cases.

		Scopes Needed: Application.Read.All
	
	.PARAMETER DisplayName
		DisplayName of the App Registration to resolve.
	
	.PARAMETER ApplicationId
		ApplicationId (ClientID) of the App Registration to resolve.
	
	.PARAMETER ObjectId
		ObjectId of the App Registration to resolve.
	
	.PARAMETER Cache
		A hashtable used as cache for resolved App Registrations.
		The content of that hashtable will be updated by the results of this command.
		Provide it repeatedly to new calls to this command to avoid repeated resolutions.
	
	.PARAMETER Unique
		Whether ambiguous results should be considered an error.
	
	.PARAMETER Services
		A hashtable mapping which EntraAuth service should be called for Graph requests.
		Example: @{ Graph = 'GraphBeta' }
		Generally, this parameter should receive a passed through -ServiceMap parameter from a public command.
	
	.EXAMPLE
		PS C:\> Resolve-Application -DisplayName "MyWebApp" -Unique
	
		Resolves the App Registration with the display name "MyWebApp", will fail if multiple apps with that name exist.
	#>
	[CmdletBinding()]
	param (
		[AllowEmptyString()]
		[AllowNull()]
		[string]
		$DisplayName,

		[Alias('AppId', 'ClientID')]
		[AllowEmptyString()]
		[AllowNull()]
		[string]
		$ApplicationId,

		[Alias('Id')]
		[AllowEmptyString()]
		[AllowNull()]
		[string]
		$ObjectId,

		[hashtable]
		$Cache = @{ },

		[switch]
		$Unique,

		[hashtable]
		$Services = @{}
	)
	process {
		$appIdentifier = "$($DisplayName)|$($ApplicationId)|$($ObjectId)"
		$result = [PSCustomObject]@{
			Success = $false
			Result = $null
			Message = ''
		}

		if ($Cache.Keys -contains $appIdentifier) {
			$result.Result = $Cache[$appIdentifier]
		}
		else {
			$param = @{ ServiceMap = $Services }
			if ($DisplayName) { $param.DisplayName = $DisplayName }
			if ($ApplicationId) { $param.ApplicationId = $ApplicationId }
			if ($ObjectId) { $param.ObjectId = $ObjectId }
	
			$result.Result = Get-EAGAppRegistration @param
			$Cache[$appIdentifier] = $result.Result
		}

		if (-not $result.Result) {
			$result.Message = "No application found! (Name: $DisplayName | AppID: $ApplicationId | ID: $ObjectId)"
			return $result
		}
		if ($result.Result.Count -gt 1 -and $Unique) {
			$names = @($result.Result).ForEach{ '+ {0} (Created: {1:yyyy-MM-dd} | ID: {2} | AppID: {3})' -f $_.DisplayName, $_.Object.createdDateTime, $_.Id, $_.AppID }
			$result.Message = "Ambiguous Application: More than one App Registration was found to add Scopes to:`n$($names -join "`n")`nPlease provide a unique identifier and try again."
			return $result
		}
		$result.Success = $true
		$result
	}
}