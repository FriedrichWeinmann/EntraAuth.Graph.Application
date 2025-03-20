function Resolve-ServicePrincipal {
	[CmdletBinding()]
	param (
		[string]
		$Identity,

		[string[]]
		$Properties = @('id', 'appid', 'displayName', 'servicePrincipalType', 'servicePrincipalNames', 'appRoles', 'oauth2PermissionScopes', 'resourceSpecificApplicationPermissions'),

		[hashtable]
		$Cache = @{},

		[switch]
		$Unique,

		[hashtable]
		$Services
	)
	process {
		if ($Properties -notcontains 'id') { $Properties = @($Properties) + 'id' }
		if ($Properties -notcontains 'appid') { $Properties = @($Properties) + 'appid' }
		if ($Properties -notcontains 'displayName') { $Properties = @($Properties) + 'displayName' }
		if ($Properties -notcontains 'servicePrincipalNames') { $Properties = @($Properties) + 'servicePrincipalNames' }

		$result = [PSCustomObject]@{
			Success = $false
			Result  = $null
			Message = ''
		}

		if ($cache.Keys -contains $Identity) {
			$result.Result = $cache[$Identity]
		}
		else {
			$filter = "serviceprincipalNames/any(x:x eq '$Identity') or displayName eq '$Identity'"
			if ($Identity -as [guid]) {
				$filter = "id eq '$Identity' or appId eq '$Identity' or serviceprincipalNames/any(x:x eq '$Identity') or displayName eq '$Identity'"
			}
			$result.Result = Get-EAGServicePrincipal -Filter $filter -Properties $Properties -ServiceMap $services

			# De-Ambiguate to unique identifiers in case of multiple results
			if ($result.Result.Count -gt 1) {
				if ($result.Result.id -contains $Identity) { $result.Result = $result.Result | Where-Object id -EQ $Identity }
				elseif ($result.Result.appId -contains $Identity) { $result.Result = $result.Result | Where-Object appId -EQ $Identity }
				elseif ($result.Result.servicePrincipalNames -contains $Identity) { $result.Result = $result.Result | Where-Object servicePrincipalNames -Contains $Identity }
			}

			$cache[$Identity] = $result.Result
		}

		if (-not $result.Result) {
			$result.Message = "Resource not found: $Identity"
			return $result
		}
		if ($servicePrincipal.Count -gt 1 -and $Unique) {
			$names = @($servicePrincipal).ForEach{ '+ {0} (ID: {1} | AppID: {2})' -f $_.DisplayName, $_.Id, $_.AppID }
			$result.Message = "Ambiguous Resource: More than one Service Principal was found for the specified name:`n$($names -join "`n")`nPlease provide a unique identifier and try again."
			return $result
		}
		$result.Success = $true
		$result
	}
}