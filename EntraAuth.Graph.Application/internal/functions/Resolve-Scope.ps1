function Resolve-Scope {
	<#
	.SYNOPSIS
		Resolves scopes, from either name or ID, into a standardized object.
	
	.DESCRIPTION
		Resolves scopes, from either name or ID, into a standardized object.
		These scopes are cached for performance reasons.

		Scope Needed: Application.Read.All
	
	.PARAMETER Scope
		Name or ID of the scope to resolve.
	
	.PARAMETER Resource
		The resource (API) to which the permissions/scopes apply.
        This can be specified as a display name, application ID, object ID or Service Principal Name.
        Examples:
        + 'Microsoft Graph'
        + '00000003-0000-0000-c000-000000000000'
        + 'https://graph.microsoft.com'
	
	.PARAMETER Type
		Type of the scope to resolve.
		Valid Options:
		- Delegated: Permissions that apply to interactive sessions, where the application acts on behalf of the signed-in user.
		- Application: Permissions that apply to unattended sessions, where the application acts as itself.
	
	.PARAMETER Services
		A hashtable mapping which EntraAuth service should be called for Graph requests.
		Example: @{ Graph = 'GraphBeta' }
		Generally, this parameter should receive a passed through -ServiceMap parameter from a public command.
	
	.EXAMPLE
		PS C:\> Resolve-Scope -Scope "User.Read.All" -Resource "Microsoft Graph" -Type Application
		
		Resolves the User.Read.All application permission for Microsoft Graph.
	#>
	[CmdletBinding()]
	param (
		[string]
		$Scope,

		[string]
		$Resource,

		[ValidateSet('Delegated', 'Application')]
		[string]
		$Type,

		[hashtable]
		$Services = @{}
	)
	process {
		$identity = "$Scope|$Resource|$Type"
		if ($script:cache.ResolvedScopes[$identity]) { return $script:cache.ResolvedScopes[$identity] }

		$filter = "serviceprincipalNames/any(x:x eq '$Resource')"
		if ($Resource -as [Guid]) { $filter = "id eq '$Resource' or appId eq '$Resource' or serviceprincipalNames/any(x:x eq '$Resource')" }
		$servicePrincipal = Get-EAGServicePrincipal -ServiceMap $Services -Filter $filter

		if (-not $servicePrincipal) {
			$script:cache.ResolvedScopes[$identity] = [PSCustomObject]@{
				ID              = '00000000-0000-0000-0000-000000000000'
				Value           = '<not identified>'
				ConsentRequired = $null
				Resource        = '00000000-0000-0000-0000-000000000000'
				ResourceName    = 'Unknown'
				Type            = 'Unknown'
			}
			return $script:cache.ResolvedScopes[$identity]
		}

		if ($servicePrincipal.Count -gt 1) {
			if ($servicePrincipal | Where-Object Id -EQ $Resource) { $servicePrincipal = $servicePrincipal | Where-Object Id -EQ $Resource }
			elseif ($servicePrincipal | Where-Object AppId -EQ $Resource) { $servicePrincipal = $servicePrincipal | Where-Object AppId -EQ $Resource }
			else { $servicePrincipal = $servicePrincipal | Select-Object -First 1 }
		}

		foreach ($scopeEntry in $servicePrincipal.Scopes.Delegated) {
			$entry = [PSCustomObject]@{
				ID              = $scopeEntry.id
				Value           = $scopeEntry.value
				ConsentRequired = $scopeEntry.type -eq 'Admin'
				Resource        = $servicePrincipal.Id
				ResourceName    = $servicePrincipal.DisplayName
				Type            = 'Delegated'
			}
			$script:cache.ResolvedScopes["$($entry.ID)|$Resource|Delegated"] = $entry
			$script:cache.ResolvedScopes["$($entry.Value)|$Resource|Delegated"] = $entry
			$script:cache.ResolvedScopes["$($entry.ID)|$($servicePrincipal.Id)|Delegated"] = $entry
			$script:cache.ResolvedScopes["$($entry.Value)|$($servicePrincipal.Id)|Delegated"] = $entry
			$script:cache.ResolvedScopes["$($entry.ID)|$($servicePrincipal.AppId)|Delegated"] = $entry
			$script:cache.ResolvedScopes["$($entry.Value)|$($servicePrincipal.AppId)|Delegated"] = $entry
		}
		foreach ($scopeEntry in $servicePrincipal.Scopes.Application) {
			$entry = [PSCustomObject]@{
				ID              = $scopeEntry.id
				Value           = $scopeEntry.value
				ConsentRequired = $true
				Resource        = $servicePrincipal.Id
				ResourceName    = $servicePrincipal.DisplayName
				Type            = 'Application'
			}
			$script:cache.ResolvedScopes["$($entry.ID)|$Resource|Application"] = $entry
			$script:cache.ResolvedScopes["$($entry.Value)|$Resource|Application"] = $entry
			$script:cache.ResolvedScopes["$($entry.ID)|$($servicePrincipal.Id)|Application"] = $entry
			$script:cache.ResolvedScopes["$($entry.Value)|$($servicePrincipal.Id)|Application"] = $entry
			$script:cache.ResolvedScopes["$($entry.ID)|$($servicePrincipal.AppId)|Application"] = $entry
			$script:cache.ResolvedScopes["$($entry.Value)|$($servicePrincipal.AppId)|Application"] = $entry
		}

		if ($script:cache.ResolvedScopes[$identity]) { return $script:cache.ResolvedScopes[$identity] }

		# Case: Scope not found
		$script:cache.ResolvedScopes[$identity] = [PSCustomObject]@{
			ID              = '00000000-0000-0000-0000-000000000000'
			Value           = '<not identified>'
			ConsentRequired = $null
			Resource        = '00000000-0000-0000-0000-000000000000'
			ResourceName    = 'Unknown'
			Type            = 'Unknown'
		}
		return $script:cache.ResolvedScopes[$identity]
	}
}