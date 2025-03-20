function Remove-EAGAppScope {
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

		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string[]]
		$Scope,

		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[ValidateSet('Delegated','Application')]
		[string]
		$Type,

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
			$scopeEntry = Resolve-Scope -Scope $entry -Resource $servicePrincipal.ID -Type $Type -Services $services
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
				if ($entry.id -in $resolvedScopes.ID) { continue }
				$newAccess.resourceAccess += $entry
			}
		}
		if ($newAccess.resourceAccess.Count -gt 0) {
			$body.requiredResourceAccess += $newAccess
		}

		Write-Verbose ($body | ConvertTo-Json -Depth 99)

		if (-not $PSCmdlet.ShouldProcess($application.Id, "Removing scopes $($resolvedScopes.Value -join ', ')")) { return }

		try { $null = Invoke-EntraRequest -Method PATCH -Path "applications/$($application.Id)" -Body $body -Header @{ 'content-type' = 'application/json' } }
		catch {
			$PSCmdlet.WriteError($_)
			return
		}
	}
}