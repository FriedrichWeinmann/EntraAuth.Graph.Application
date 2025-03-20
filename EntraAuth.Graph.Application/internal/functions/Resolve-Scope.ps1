function Resolve-Scope {
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
		$Services
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