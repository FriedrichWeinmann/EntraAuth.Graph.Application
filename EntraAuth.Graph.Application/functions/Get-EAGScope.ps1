function Get-EAGScope {
	<#
	.SYNOPSIS
		Lists scopes applied to app registrations, service principals, and managed identities.
	
	.DESCRIPTION
		Lists scopes applied to app registrations, service principals, and managed identities.

		Scopes Needed: Application.Read.All, User.ReadBasic.All (Delegated), User.Read.All (Application)
	
	.PARAMETER Type
		Filter scopes by type.
		Valid Options:
		- All: All scopes (default)
		- Delegated: Delegated scopes
		- Application: Application scopes
	
	.PARAMETER DisplayName
		The displayname of the app registration or service principal to filter by.
	
	.PARAMETER ApplicationId
		The Application ID (Client ID) of the app registration or service principal to filter by.
	
	.PARAMETER ObjectId
		The Object ID of the app registration or service principal to filter by.
	
	.PARAMETER ClearCache
		Indicates whether to clear the cache of resolved scopes and principals.
		This should only be needed when developing an application and modifying/updating scope definitions.
	
	.PARAMETER ServiceMap
		Optional hashtable to map service names to specific EntraAuth service instances.
        Used for advanced scenarios where you want to use something other than the default Graph connection.
        Example: @{ Graph = 'GraphBeta' }
        This will switch all Graph API calls to use the beta Graph API.
	
	.EXAMPLE
		PS C:\> Get-EAGScope -DisplayName "MyWebApp"
	
		Retrieves all scopes applied to the app registration or service principal with the display name "MyWebApp".

	.EXAMPLE
		PS C:\> Get-EAGScope -ApplicationId "11111111-1111-1111-1111-111111111111"
	
		Retrieves all scopes applied to the app registration or service principal with the specified application ID.
	#>
	[CmdletBinding(DefaultParameterSetName = 'Filter')]
	param (
		[ValidateSet('All', 'Delegated', 'Application')]
		[string]
		$Type = 'All',

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

		[switch]
		$ClearCache,

		[hashtable]
		$ServiceMap = @{}
	)

	begin {
		$services = $script:serviceSelector.GetServiceMap($ServiceMap)

		Assert-EntraConnection -Service $services.Graph -Cmdlet $PSCmdlet

		#region Functions
		function Get-DelegateScope {
			[CmdletBinding()]
			param (
				[AllowNull()]
				$Application,

				$ServicePrincipal,

				[hashtable]
				$Services
			)

			$grants = Invoke-EntraRequest -Service $Services.Graph -Path oauth2PermissionGrants -Query @{
				'$filter' = "clientId eq '$($ServicePrincipal.Id)'"
			}

			#region Process Granted Scopes
			$scopesProcessed = @{}

			foreach ($grant in $grants) {
				$principal = Resolve-ScopePrincipal -ID $grant.principalId -Services $Services
				foreach ($scope in $grant.scope.Trim() -split ' ') {
					$scopeData = Resolve-Scope -Scope $scope -Resource $grant.resourceId -Type 'Delegated' -Services $Services
					
					[PSCustomObject]@{
						PSTypeName      = 'EntraAuth.Graph.Scope'
						ApplicationId   = $ServicePrincipal.AppID
						ApplicationName = $ServicePrincipal.DisplayName
						Resource        = $grant.resourceId
						ResourceName    = $script:cache.ServicePrincipalByID."$($grant.resourceId)".displayName
						Type            = 'Delegated'
						Scope           = $scopeData.Id
						ScopeName       = $scopeData.value
						ConsentRequired = $scopeData.ConsentRequired
						HasConsent      = $true
						PrincipalName   = $principal.Name
						PrincipalID     = $principal.ID
					}

					$scopesProcessed[$scopeData.id] = $scopeData
				}
			}
			#endregion Process Granted Scopes

			if (-not $Application) { return }

			#region Process Non-Granted Scopes
			foreach ($resourceReq in $Application.requiredResourceAccess) {
				foreach ($resourceEntry in $resourceReq.resourceAccess) {
					if ($resourceEntry.type -ne 'Scope') { continue }
					if ($scopesProcessed[$resourceEntry.id]) { continue }

					$scopeData = Resolve-Scope -Scope $resourceEntry.id -Resource $resourceReq.resourceAppId -Type 'Delegated' -Services $Services

					[PSCustomObject]@{
						PSTypeName      = 'EntraAuth.Graph.Scope'
						ApplicationId   = $ServicePrincipal.AppID
						ApplicationName = $ServicePrincipal.DisplayName
						Resource        = $resourceReq.resourceAppId
						ResourceName    = $scopeData.ResourceName
						Type            = 'Delegated'
						Scope           = $scopeData.Id
						ScopeName       = $scopeData.value
						ConsentRequired = $scopeData.ConsentRequired
						HasConsent      = $false
						PrincipalName   = $null
						PrincipalID     = $null
					}
				}
			}
			#endregion Process Non-Granted Scopes
		}
		function Get-ApplicationScope {
			[CmdletBinding()]
			param (
				[AllowNull()]
				$Application,

				$ServicePrincipal,

				[hashtable]
				$Services
			)

			#region Process Granted Scopes
			$scopesProcessed = @{}

			$appRoleAssignments = Invoke-EntraRequest -Service $Services.Graph -Path "servicePrincipals/$($ServicePrincipal.id)/appRoleAssignments"
			foreach ($roleAssignment in $appRoleAssignments) {
				$scopeData = Resolve-Scope -Scope $roleAssignment.appRoleId -Resource $roleAssignment.resourceId -Type 'Application' -Services $Services

				[PSCustomObject]@{
					PSTypeName      = 'EntraAuth.Graph.Scope'
					ApplicationId   = $ServicePrincipal.AppID
					ApplicationName = $ServicePrincipal.DisplayName
					Resource        = $roleAssignment.resourceId
					ResourceName    = $roleAssignment.resourceDisplayName
					Type            = 'Application'
					Scope           = $scopeData.Id
					ScopeName       = $scopeData.value
					ConsentRequired = $true
					HasConsent      = $true
					PrincipalName   = $null
					PrincipalID     = $null
				}

				$scopesProcessed[$scopeData.id] = $scopeData
			}
			#endregion Process Granted Scopes
			
			if (-not $Application) { return }

			#region Process Non-Granted Scopes
			foreach ($resourceReq in $Application.requiredResourceAccess) {
				foreach ($resourceEntry in $resourceReq.resourceAccess) {
					if ($resourceEntry.type -ne 'Role') { continue }
					if ($scopesProcessed[$resourceEntry.id]) { continue }

					$scopeData = Resolve-Scope -Scope $resourceEntry.id -Resource $resourceReq.resourceAppId -Type 'Application' -Services $Services

					[PSCustomObject]@{
						PSTypeName      = 'EntraAuth.Graph.Scope'
						ApplicationId   = $ServicePrincipal.AppID
						ApplicationName = $ServicePrincipal.DisplayName
						Resource        = $resourceReq.resourceAppId
						ResourceName    = $scopeData.ResourceName
						Type            = 'Application'
						Scope           = $scopeData.Id
						ScopeName       = $scopeData.value
						ConsentRequired = $true
						HasConsent      = $false
						PrincipalName   = $null
						PrincipalID     = $null
					}
				}
			}
			#endregion Process Non-Granted Scopes
		}
		#endregion Functions

		if ($ClearCache) {
			$script:cache.ResolvedScopes.Clear()
			$script:cache.Principals.Clear()
		}
	}
	process {
		$param = @{}
		if ($DisplayName) { $param.DisplayName = $DisplayName }
		if ($ApplicationId) { $param.ApplicationId = $ApplicationId }
		if ($ObjectId) { $param.ObjectId = $ObjectId }

		$servicePrincipals = Get-EAGServicePrincipal @param -Properties id, appid, displayName, servicePrincipalType, appRoles, oauth2PermissionScopes, resourceSpecificApplicationPermissions -ServiceMap $ServiceMap
		foreach ($servicePrincipal in $servicePrincipals) {
			$application = Get-EAGAppRegistration -ApplicationId $servicePrincipal.AppID -ServiceMap $ServiceMap -Raw

			if ($Type -in 'All', 'Delegated') {
				Get-DelegateScope -Application $application -ServicePrincipal $servicePrincipal -Services $services
			}
			if ($Type -in 'All', 'Application') {
				Get-ApplicationScope -Application $application -ServicePrincipal $servicePrincipal -Services $services
			}
		}
	}
}