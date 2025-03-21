function Grant-EAGScopeConsent {
	<#
	.SYNOPSIS
		Grants consent for a scope on an App Registration.
	
	.DESCRIPTION
		Grants consent for a scope on an App Registration.
		Consent is required for scopes configured on an app registration to take effect in the tenant.

		The App Registration is a manifest, the declaration of the application in use.
		The Enterprise Application / Service Principal is the actual object that represents the application in the tenant.
		Granting "Admin Consent" to scopes on an App Registration will copy those onto the Enterprise Application / Service Principal, hence making them take effect.

		Note:
		Managed Identities are also Service Principals, but they do not have an App Registration.
		There is no consent of "Consent", as there is no manifest's proposal to consent to.
		This does not mean that Managed Identities cannot have scopes, but they require a different approach.
		Use "Add-EAGMsiScope" to add scopes to Managed Identities.

		Scopes Needed: Application.Read.All, AppRoleAssignment.ReadWrite.All
	
	.PARAMETER DisplayName
		Display name of the app registration whose scopes to grant consent to.
	
	.PARAMETER ApplicationId
		Application ID (Client ID) of the app registration whose scopes to grant consent to.
	
	.PARAMETER ObjectId
		Object ID of the app registration whose scopes to grant consent to.
	
	.PARAMETER Scope
		The permission scopes to grant consent to.
	
	.PARAMETER Type
		Type of the permission scopes to grant consent to.
		Valid Options:
		- Delegated: Permissions that apply to interactive sessions, where the application acts on behalf of the signed-in user.
		- Application: Permissions that apply to unattended sessions, where the application acts as itself.
	
	.PARAMETER Resource
		%RESOURCE%
	
	.PARAMETER ServiceMap
		%SERVICEMAP%
	
	.EXAMPLE
		PS C:\> Grant-EAGScopeConsent -DisplayName "MyWebApp" -Resource "Microsoft Graph" -Scope "User.Read.All" -Type Application

		Grants consent for the User.Read.All application permission for Microsoft Graph to the app registration named "MyWebApp".

	.EXAMPLE
		PS C:\> Grant-EAGScopeConsent -ApplicationId "11111111-1111-1111-1111-111111111111" -Resource "00000003-0000-0000-c000-000000000000" -Scope "User.Read.All", "Group.Read.All" -Type Delegated

		Grants consent for the User.Read.All and Group.Read.All delegated permissions for Microsoft Graph (identified by its app ID) to the app registration with the specified application ID.

	.EXAMPLE
		PS C:\> Get-EAGAppRegistration -DisplayName MyTaskApp | Grant-EAGScopeConsent -Resource "https://graph.microsoft.com" -Scope "User.ReadBasic.All" -Type Delegated

		Grants consent for the User.ReadBasic.All delegated permission for Microsoft Graph to the app registration named "MyTaskApp".
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
		
		$newDelegateGrants = @()
		foreach ($resolvedScope in $resolvedScopes) {
			if ($resolvedScope.Type -eq 'Application' -and $resolvedScope.ID -in $applicationGrants.appRoleId) {
				Write-Verbose "Skipping Application scope $($resolvedScope.Value) - already consented on $($application.DisplayName)"
				continue
			}
			if ($resolvedScope.Type -eq 'Delegated' -and $resolvedScope.Value -in @($delegatedGrants.scope -split ' ').ForEach{$_.Trim()}) {
				Write-Verbose "Skipping Delegated scope $($resolvedScope.Value) - already consented on $($application.DisplayName)"
				continue
			}

			if (-not $PSCmdlet.ShouldProcess("$($application.DisplayName) ($($application.AppID))", "Grant consent for scope $($resolvedScope.Value) of resource $($resolvedScope.ResourceName)")) {
				continue
			}

			Write-Verbose "Processing scope:`n$($resolvedScope | ConvertTo-Json)"
			switch ($resolvedScope.Type) {
				'Application' {
					$grant = @{
						"principalId" = $appSPN.id
						"resourceId"  = $resolvedScope.Resource
						"appRoleId"   = $resolvedScope.ID
					}
					Write-Verbose "Granting Admin consent for scope $($resolvedScope.id) ($($resolvedScope.Value))) on $($appSPN.appid) ($($appSPN.displayName))"
					try {
						$null = Invoke-EntraRequest -Method POST -Path "servicePrincipals/$($appSPN.id)/appRoleAssignments" -Body $grant -Header @{
							'content-type' = 'application/json'
						}
					}
					catch {
						Write-Error $_
					}
				}
				'Delegated' {
					$newDelegateGrants += $resolvedScope
				}
				default {
					Write-Error "Unexpected scope type: $($resolvedScope.Type)"
				}
			}
		}
		
		if (-not $newDelegateGrants) { return }

		$byResource = $newDelegateGrants | Group-Object Resource
		foreach ($group in $byResource) {
			$scopeGrant = $group.Group.Value
			$applicableGrant = $delegatedGrants | Where-Object resourceId -eq $group.Name
			if ($applicableGrant) {
				$scopeGrant = @(@($applicableGrant.Scope -split " ").ForEach{ $_.Trim() }) + $scopeGrant
			}
			$exampleScope = $group.Group[0]

			$grant = @{
				"clientId"    = $appSPN.id
				"consentType" = "AllPrincipals"
				"principalId" = $null
				"resourceId"  = $exampleScope.Resource
				"scope"       = $scopeGrant -join " "
				"expiryTime"  = "2299-12-31T00:00:00Z"
			}
			Write-Verbose "Granting Admin consent for scope(s) $($group.Group.Value -join ', ') on $($appSPN.appid) ($($appSPN.displayName))"

			$method = 'POST'
			$apiPath = 'oauth2PermissionGrants'
			if ($applicableGrant) {
				$method = 'PATCH'
				$apiPath = "oauth2PermissionGrants/$($applicableGrant.id)"
				$grant = @{
					scope = $scopeGrant -join " "
				}
			}
			try {
				$null = Invoke-EntraRequest -Method $method -Path $apiPath -Body $grant -Header @{
					'content-type' = 'application/json'
				}
			}
			catch {
				Write-Error $_
			}
		}
	}
}