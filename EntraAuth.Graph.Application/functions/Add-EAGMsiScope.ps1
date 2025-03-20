function Add-EAGMsiScope {
	[CmdletBinding(DefaultParameterSetName = 'Filter', SupportsShouldProcess = $true)]
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
		[string]
		$Resource,

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
			$scopeEntry = Resolve-Scope -Scope $entry -Resource $servicePrincipal.ID -Type 'Application' -Services $services
			if ($scopeEntry.ScopeName -eq '<not identified>') {
				Write-Error "Scope $entry of type $Type not found on Service Principal $($servicePrincipal.DisplayName) ($($servicePrincipal.ID) | $Resource)"
				continue
			}
			$scopeEntry
		}
		if (-not $resolvedScopes) {
			Invoke-TerminatingException -Cmdlet $PSCmdlet -Message "No valid scopes found! Use 'Get-EAGScopeDefinition' to find the valid scopes for the resource and try again."
		}

		$servicePrincipals = @{}
	}
	process {
		#region Resolve Application Data
		$identity = $ObjectId
		if (-not $identity) { $identity = $ApplicationId }
		if (-not $identity) { $identity = $DisplayName }
		if (-not $identity) {
			Write-Error -Message "Managed Identity not specified! Provide at least one of ObjectId, ApplicationId or DisplayName."
			return
		}
		$result = Resolve-ServicePrincipal -Identity $identity -Properties id, appId, displayName -Cache $servicePrincipals -Unique -Services $services
		if (-not $result.Success) {
			Write-Error "Error resolving Managed Identity for $($identity):`n$($result.Message)"
			return
		}
		$appSPN = $result.Result
		#endregion Resolve Application Data

		$applicationGrants = Invoke-EntraRequest -Service $services.Graph -Path "servicePrincipals/$($appSPN.id)/appRoleAssignments"

		foreach ($resolvedScope in $resolvedScopes) {
			if ($resolvedScope.ID -in $applicationGrants.appRoleId) {
				Write-Verbose "Skipping Application scope $($resolvedScope.Value) - already added to $($appSPN.DisplayName)"
				continue
			}

			if (-not $PSCmdlet.ShouldProcess("$($appSPN.DisplayName) ($($appSPN.AppID))", "Grant consent for scope $($resolvedScope.Value) of resource $($resolvedScope.ResourceName)")) {
				continue
			}

			Write-Verbose "Processing scope:`n$($resolvedScope | ConvertTo-Json)"
			$grant = @{
				"principalId" = $appSPN.id
				"resourceId"  = $resolvedScope.Resource
				"appRoleId"   = $resolvedScope.ID
			}
			Write-Verbose "Adding scope $($resolvedScope.id) ($($resolvedScope.Value))) to Managed Identity $($appSPN.appid) ($($appSPN.displayName))"
			try {
				$null = Invoke-EntraRequest -Method POST -Path "servicePrincipals/$($appSPN.id)/appRoleAssignments" -Body $grant -Header @{
					'content-type' = 'application/json'
				}
			}
			catch {
				Write-Error $_
			}
		}
	}
}