function Revoke-EAGScopeConsent {
	<#
	.SYNOPSIS
		Revokes previously granted consent for scopes on an App Registration.
	
	.DESCRIPTION
		Revokes previously granted consent for scopes on an App Registration.
		Consent is required for scopes configured on an app registration to take effect in the tenant.
	
		Scopes Needed: Application.Read.All, AppRoleAssignment.ReadWrite.All
	
	.PARAMETER DisplayName
		Displayname of the app registration whose scopes to revoke consent for.
	
	.PARAMETER ApplicationId
		Application ID (Client ID) of the app registration whose scopes to revoke consent for.
	
	.PARAMETER ObjectId
		Object ID of the app registration whose scopes to revoke consent for.
	
	.PARAMETER Scope
		The permission scopes to revoke consent for.
	
	.PARAMETER Type
		Type of the permission scopes to revoke consent for.
		Valid Options:
		- Delegated: Permissions that apply to interactive sessions, where the application acts on behalf of the signed-in user.
		- Application: Permissions that apply to unattended sessions, where the application acts as itself.
	
	.PARAMETER Resource
		The resource (API) to which the permissions/scopes apply.
        This can be specified as a display name, application ID, object ID or Service Principal Name.
        Examples:
        + 'Microsoft Graph'
        + '00000003-0000-0000-c000-000000000000'
        + 'https://graph.microsoft.com'
	
	.PARAMETER ServiceMap
		Optional hashtable to map service names to specific EntraAuth service instances.
        Used for advanced scenarios where you want to use something other than the default Graph connection.
        Example: @{ Graph = 'GraphBeta' }
        This will switch all Graph API calls to use the beta Graph API.

	.PARAMETER WhatIf
		If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.
	
	.PARAMETER Confirm
		If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.
	
	.EXAMPLE
		PS C:\> Revoke-EAGScopeConsent -DisplayName "MyWebApp" -Resource "Microsoft Graph" -Scope "User.Read.All" -Type Application
	
		Revokes consent for the User.Read.All application permission for Microsoft Graph from the app registration named "MyWebApp".
	#>
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
		[ValidateSet('Delegated', 'Application')]
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
		$applications = @{ }
		$servicePrincipals = @{ }
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
		$result = Resolve-Application -DisplayName $DisplayName -ApplicationId $ApplicationId -ObjectId $ObjectId -Cache $applications -Unique -Services $services
		if (-not $result.Success) {
			Write-Error $result.Message
			return
		}
		$application = $result.Result

		$result = Resolve-ServicePrincipal -Identity $application.AppID -Properties id -Cache $servicePrincipals -Unique -Services $services
		if (-not $result.Success) {
			Write-Error "Error resolving Enterprise Application for $($application.AppID):`n$($result.Message)"
			return
		}
		$appSPN = $result.Result
		#endregion Resolve Application Data

		$applicationGrants = Invoke-EntraRequest -Service $services.Graph -Path "servicePrincipals/$($appSPN.id)/appRoleAssignments"
		$delegatedGrants = Invoke-EntraRequest -Service $services.Graph -Path 'oauth2PermissionGrants' -Query @{ '$filter' = "clientId eq '$($appSPN.id)' and consentType eq 'AllPrincipals'" }

		$oldDelegateGrants = @()
		foreach ($resolvedScope in $resolvedScopes) {
			if ($resolvedScope.Type -eq 'Application' -and $resolvedScope.ID -notin $applicationGrants.appRoleId) {
				Write-Verbose "Skipping Application scope $($resolvedScope.Value) - no consent found for $($application.DisplayName)"
				continue
			}
			if ($resolvedScope.Type -eq 'Delegated' -and $resolvedScope.Value -notin @($delegatedGrants.scope -split ' ').ForEach{ $_.Trim() }) {
				Write-Verbose "Skipping Delegated scope $($resolvedScope.Value) - no consent found for $($application.DisplayName)"
				continue
			}

			if (-not $PSCmdlet.ShouldProcess("$($application.DisplayName) ($($application.AppID))", "Revoke consent for scope $($resolvedScope.Value) of resource $($resolvedScope.ResourceName)")) {
				continue
			}

			Write-Verbose "Processing scope:`n$($resolvedScope | ConvertTo-Json)"
			switch ($resolvedScope.Type) {
				'Application' {
					$toRevoke = $applicationGrants | Where-Object appRoleId -EQ $resolvedScope.ID
					Write-Verbose "Revoking Admin consent for scope $($resolvedScope.id) ($($resolvedScope.Value))) on $($appSPN.appid) ($($appSPN.displayName))"
					try {
						$null = Invoke-EntraRequest -Method DELETE -Path "servicePrincipals/$($appSPN.id)/appRoleAssignments/$($toRevoke.id)" -Header @{
							'content-type' = 'application/json'
						}
					}
					catch {
						Write-Error $_
					}
				}
				'Delegated' {
					$oldDelegateGrants += $resolvedScope
				}
				default {
					Write-Error "Unexpected scope type: $($resolvedScope.Type)"
				}
			}
		}
		
		if (-not $oldDelegateGrants) { return }

		$byResource = $oldDelegateGrants | Group-Object Resource
		foreach ($group in $byResource) {
			$applicableGrant = $delegatedGrants | Where-Object resourceId -eq $group.Name
			$survivingScopes = @($applicableGrant.Scope -split " ").ForEach{ $_.Trim() } | Where-Object { $_ -notin $group.Group.Value }

			Write-Verbose "Revoking Admin consent for scope(s) $($group.Group.Value -join ', ') on $($appSPN.appid) ($($appSPN.displayName))"
			if (-not $survivingScopes) {
				try {
					$null = Invoke-EntraRequest -Method DELETE -Path "oauth2PermissionGrants/$($applicableGrant.id)" -Header @{
						'content-type' = 'application/json'
					}
				}
				catch {
					Write-Error $_
				}
				continue
			}
			
			$grant = @{
				scope = $survivingScopes -join " "
			}
			try {
				$null = Invoke-EntraRequest -Method 'PATCH' -Path "oauth2PermissionGrants/$($applicableGrant.id)" -Body $grant -Header @{
					'content-type' = 'application/json'
				}
			}
			catch {
				Write-Error $_
			}
		}
	}
}