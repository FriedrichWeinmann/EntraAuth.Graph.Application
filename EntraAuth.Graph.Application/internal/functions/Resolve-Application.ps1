function Resolve-Application {
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
		$Services
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