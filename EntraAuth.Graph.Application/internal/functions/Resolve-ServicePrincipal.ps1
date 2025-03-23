function Resolve-ServicePrincipal {
	<#
	.SYNOPSIS
		Resolves Service Principals, based on an identifiable property.
	
	.DESCRIPTION
		Resolves Service Principals, based on an identifiable property.
		These Service Principals are cached for performance reasons.

		Valid identifiers:
		- DisplayName
		- Client ID (App ID)
		- Object ID
		- Service Principal Name

		This command always returns an obbject with the following properties:
		- Success: A boolean indicating if the resolution was successful.
		- Result: The resolved App Registration object(s).
		- Message: A message indicating the result of the resolution.
		The caller is responsible for handling error cases.

		Scopes Needed: Application.Read.All
	
	.PARAMETER Identity
		The identifier of the Service Principal to resolve.
		Valid identifiers:
		- DisplayName
		- Client ID (App ID)
		- Object ID
		- Service Principal Name
	
	.PARAMETER Properties
		Specific properties to retrieve from the Service Principal objects.
		Will always include 'id', 'appid', 'displayName', and 'servicePrincipalNames', no matter what is specified.
	
	.PARAMETER Cache
		A hashtable used as cache for resolved Service Principals.
		The content of that hashtable will be updated by the results of this command.
		Provide it repeatedly to new calls to this command to avoid repeated resolutions.
	
	.PARAMETER Unique
		Whether ambiguous results should be considered an error.
	
	.PARAMETER Services
		A hashtable mapping which EntraAuth service should be called for Graph requests.
		Example: @{ Graph = 'GraphBeta' }
		Generally, this parameter should receive a passed through -ServiceMap parameter from a public command.
	
	.EXAMPLE
		PS C:\> Resolve-ServicePrincipal -Identity "Microsoft Graph" -Cache $spns
	
		Resolves the Service Principal with the display name "Microsoft Graph".

	.EXAMPLE
		PS C:\> Resolve-ServicePrincipal -Identity "https://graph.microsoft.com" -Cache $spns
	
		Resolves the Service Principal with the specified Service Principal Name.
	#>
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
		$Services = @{}
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