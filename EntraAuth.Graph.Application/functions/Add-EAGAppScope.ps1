function Add-EAGAppScope {
	[CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'Filter')]
	param (
		[Parameter(ParameterSetName = 'Filter', ValueFromPipelineByPropertyName = $true)]
		[string]
		$DisplayName,

		[Parameter(ParameterSetName = 'Filter', ValueFromPipelineByPropertyName = $true)]
		[Alias('AppId', 'ClientID')]
		[string]
		$ApplicationId,

		[Parameter(Mandatory = $true, ParameterSetName = 'Identity', ValueFromPipelineByPropertyName = $true)]
		[Alias('Id')]
		[string]
		$ObjectId,

		[Parameter(Mandatory = $true)]
		[string[]]
		$Scope,

		[Parameter(Mandatory = $true)]
		[ValidateSet('Delegated','Application')]
		[string]
		$Type,

		[Parameter(Mandatory = $true)]
		[string]
		$Resource,

		[switch]
		$Consent,

		[hashtable]
		$ServiceMap
	)
	begin {
		$services = $script:serviceSelector.GetServiceMap($ServiceMap)

		Assert-EntraConnection -Service $services.Graph -Cmdlet $PSCmdlet

		$filter = "serviceprincipalNames/any(x:x eq '$Resource') or displayName eq '$Resource'"
		if ($Resource -as [guid]) {
			$filter = "id eq '$Resource' or appId eq '$Resource' or serviceprincipalNames/any(x:x eq '$Resource') or displayName eq '$Resource'"
		}
		$servicePrincipal = Get-EAGServicePrincipal -Filter $filter -Properties id, appid, displayName, servicePrincipalType, appRoles, oauth2PermissionScopes, resourceSpecificApplicationPermissions -ServiceMap $ServiceMap
		if (-not $servicePrincipal) {
			Invoke-TerminatingException -Cmdlet $PSCmdlet -Message "Resource not found: $Resource" -Category ObjectNotFound
		}
		if ($servicePrincipal.Count -gt 1) {
			$names = @($servicePrincipal).ForEach{ '+ {0} (ID: {1} | AppID: {2})' -f $_.DisplayName, $_.Id, $_.AppID }
			Invoke-TerminatingException -Cmdlet $PSCmdlet -Message "Ambiguous Resource: More than one Service Principal was found for the specified name:`n$($names -join "`n")`nPlease provide a unique identifier and try again." -Category LimitsExceeded
		}

		$resolvedScopes = foreach ($entry in $Scope) {
			$scopeEntry = Resolve-Scope -Scope $entry -Resource $servicePrincipal.ID -Type $Type -Services $services
			if ($scopeEntry.ScopeName -eq '<not identified>') {
				Write-Error "Scope $entry of type $Type not found on Service Principal $($servicePrincipal.DisplayName) ($($servicePrincipal.ID) | $Resource)"
				continue
			}
			$scopeEntry
		}
		if (-not $resolvedScopes) {
			Invoke-TerminatingException -Cmdlet $PSCmdlet -Message "No valid scopes found! Use 'Get-EAGScopeDefinition' to find the valid scopes for the resource and try again."
		}
	}
	process {
		#region Resolve Application Data
		# Note: Can't cache, since previous process blocks might have affected the same object
		$result = Resolve-Application -DisplayName $DisplayName -ApplicationId $ApplicationId -ObjectId $ObjectId -Unique -Services $services
		if (-not $result.Success) {
			Write-Error $result.Message
			return
		}
		$application = $result.Result
		#endregion Resolve Application Data

		$body = @{
			requiredResourceAccess = @()
		}
		$newAccess = [PSCustomObject]@{
			resourceAppId = $servicePrincipal.AppId
			resourceAccess = @()
		}
		foreach ($access in $application.object.requiredResourceAccess) {
			if ($access.resourceAppId -ne $servicePrincipal.AppId) {
				$body.requiredResourceAccess += $access
				continue
			}

			foreach ($entry in $access.resourceAccess) {
				$newAccess.resourceAccess += $entry
			}
		}
		foreach ($scopeEntry in $resolvedScopes) {
			if ($newAccess.resourceAccess.id -contains $scopeEntry.ID) { continue }
			$accessEntry = [PSCustomObject]@{
				id = $scopeEntry.ID
				type = 'Scope'
			}
			if ($scopeEntry.Type -ne 'Delegated') {
				$accessEntry.type = 'Role'
			}
			$newAccess.resourceAccess += $accessEntry
		}
		$body.requiredResourceAccess += $newAccess

		Write-Verbose ($body | ConvertTo-Json -Depth 99)

		if (-not $PSCmdlet.ShouldProcess($application.Id, "Adding scopes $($resolvedScopes.Value -join ', ')")) { return }

		try { $null = Invoke-EntraRequest -Method PATCH -Path "applications/$($application.Id)" -Body $body -Header @{ 'content-type' = 'application/json' } }
		catch {
			$PSCmdlet.WriteError($_)
			return
		}

		if (-not $Consent) { return }

		Grant-EAGScopeConsent -ApplicationID $application.AppID -Scope $Scope -Type $Type -Resource $Resource
	}
}