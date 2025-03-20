function Remove-EAGMsiScope {
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

		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string[]]
		$Scope,

		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string]
		$Resource,

		[hashtable]
		$ServiceMap
	)
	begin {
		$services = $script:serviceSelector.GetServiceMap($ServiceMap)

		Assert-EntraConnection -Service $services.Graph -Cmdlet $PSCmdlet

		$principals = @{ }
		$servicePrincipals = @{}
	}
	process {
		#region Resolve Scope Data
		$result = Resolve-ServicePrincipal -Identity $Resource -Cache $principals -Unique -Services $services
		if (-not $result.Success) {
			Write-Error -Message $result.Message
			return
		}
		$servicePrincipal = $result.Result

		$resolvedScopes = foreach ($entry in $Scope) {
			$scopeEntry = Resolve-Scope -Scope $entry -Resource $servicePrincipal.ID -Type 'Application' -Services $services
			if ($scopeEntry.ScopeName -eq '<not identified>') {
				Write-Error "Scope $entry of type $Type not found on Service Principal $($servicePrincipal.DisplayName) ($($servicePrincipal.ID) | $Resource)"
				continue
			}
			$scopeEntry
		}
		if (-not $resolvedScopes) {
			Write-Error -Message "No valid scopes found! Use 'Get-EAGScopeDefinition' to find the valid scopes for the resource and try again."
			return
		}
		#endregion Resolve Scope Data

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
			if ($resolvedScope.ID -notin $applicationGrants.appRoleId) {
				Write-Verbose "Skipping Application scope $($resolvedScope.Value) - not found on $($appSPN.DisplayName)"
				continue
			}

			if (-not $PSCmdlet.ShouldProcess("$($appSPN.DisplayName) ($($appSPN.AppID))", "Removing scope $($resolvedScope.Value) of resource $($resolvedScope.ResourceName)")) {
				continue
			}

			Write-Verbose "Processing scope:`n$($resolvedScope | ConvertTo-Json)"
			$grantToKill = $applicationGrants | Where-Object appRoleId -EQ $resolvedScope.ID

			Write-Verbose "Removing scope $($resolvedScope.id) ($($resolvedScope.Value))) from Managed Identity $($appSPN.appid) ($($appSPN.displayName))"
			try {
				$null = Invoke-EntraRequest -Method DELETE -Path "servicePrincipals/$($appSPN.id)/appRoleAssignments/$($grantToKill.id)" -Header @{
					'content-type' = 'application/json'
				}
			}
			catch {
				Write-Error $_
			}
		}
	}
}