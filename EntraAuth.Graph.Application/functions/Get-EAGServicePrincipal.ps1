function Get-EAGServicePrincipal {
	<#
	.SYNOPSIS
		Lists service principals in the connected Entra ID tenant.
	
	.DESCRIPTION
		Lists service principals in the connected Entra ID tenant.

		Scope Needed: Application.Read.All
	
	.PARAMETER DisplayName
		The display name of the service principal to filter by.
	
	.PARAMETER ObjectId
		The Object ID of the service principal to filter by.
	
	.PARAMETER ApplicationId
		The Application ID (Client ID) of the service principal to filter by.
	
	.PARAMETER Filter
		Additional OData filter expression to apply when searching for service principals.
	
	.PARAMETER Properties
		Specific properties to retrieve from the service principal objects.
	
	.PARAMETER Raw
		When specified, returns the raw API response objects instead of the formatted PowerShell objects.
        Useful for accessing detailed properties not exposed at the top level, but less user-friendly.
	
	.PARAMETER ServiceMap
		Optional hashtable to map service names to specific EntraAuth service instances.
        Used for advanced scenarios where you want to use something other than the default Graph connection.
        Example: @{ Graph = 'GraphBeta' }
        This will switch all Graph API calls to use the beta Graph API.
	
	.EXAMPLE
		PS C:\> Get-EAGServicePrincipal
	
		Retrieves all service principals in the Entra ID tenant.

	.EXAMPLE
		PS C:\> Get-EAGServicePrincipal -DisplayName "MyWebApp"
	
		Retrieves the service principal with the display name "MyWebApp".

	.EXAMPLE
		PS C:\> Get-EAGServicePrincipal -DisplayName 'Dept-*' -Properties 'displayName', 'appId'
	
		Retrieves all service principals that start with "Dept-" and returns only the display name and app ID properties.
	#>
	[CmdletBinding()]
	param (
		[Parameter(ParameterSetName = 'Filter')]
		[string]
		$DisplayName,

		[Parameter(Mandatory = $true, ParameterSetName = 'Identity')]
		[Alias('Id')]
		[string]
		$ObjectId,

		[Parameter(ParameterSetName = 'Filter', ValueFromPipelineByPropertyName = $true)]
		[Alias('AppId', 'ClientID')]
		[string]
		$ApplicationId,

		[Parameter(ParameterSetName = 'Filter', ValueFromPipelineByPropertyName = $true)]
		[string]
		$Filter,

		[string[]]
		$Properties,

		[switch]
		$Raw,

		[hashtable]
		$ServiceMap = @{}
	)

	begin {
		$services = $script:serviceSelector.GetServiceMap($ServiceMap)

		Assert-EntraConnection -Service $services.Graph -Cmdlet $PSCmdlet

		function ConvertFrom-ServicePrincipal {
			[CmdletBinding()]
			param (
				[Parameter(ValueFromPipeline = $true)]
				$InputObject,

				[switch]
				$Raw
			)

			process {
				#region Feed the Cache
				if ($InputObject.AppID) {
					if (-not $script:cache.ServicePrincipalByAppID[$InputObject.AppID]) {
						$script:cache.ServicePrincipalByAppID[$InputObject.AppID] = [PSCustomObject]@{
							Type        = $InputObject.servicePrincipalType
							Id          = $InputObject.id
							AppID       = $InputObject.AppID
							DisplayName = $InputObject.DisplayName
						}
					}
					else {
						# Depending on selected we might lose individual properties if we overwrite all
						$current = $script:cache.ServicePrincipalByAppID[$InputObject.AppID]
						if ($InputObject.servicePrincipalType) { $current.Type = $InputObject.servicePrincipalType }
						if ($InputObject.id) { $current.Id = $InputObject.id }
						if ($InputObject.AppID) { $current.AppID = $InputObject.AppID }
						if ($InputObject.DisplayName) { $current.DisplayName = $InputObject.DisplayName }
					}
				}
				if ($InputObject.ID) {
					if (-not $script:cache.ServicePrincipalByID[$InputObject.ID]) {
						$script:cache.ServicePrincipalByID[$InputObject.ID] = [PSCustomObject]@{
							Type        = $InputObject.servicePrincipalType
							Id          = $InputObject.id
							AppID       = $InputObject.AppID
							DisplayName = $InputObject.DisplayName
						}
					}
					else {
						# Depending on selected we might lose individual properties if we overwrite all
						$current = $script:cache.ServicePrincipalByID[$InputObject.ID]
						if ($InputObject.servicePrincipalType) { $current.Type = $InputObject.servicePrincipalType }
						if ($InputObject.id) { $current.Id = $InputObject.id }
						if ($InputObject.AppID) { $current.AppID = $InputObject.AppID }
						if ($InputObject.DisplayName) { $current.DisplayName = $InputObject.DisplayName }
					}
				}
				foreach ($scope in $InputObject.AppRoles) {
					$script:cache.ScopesByID[$scope.id] = $scope
				}
				foreach ($scope in $InputObject.oauth2PermissionScopes) {
					$script:cache.ScopesByID[$scope.id] = $scope
				}
				foreach ($scope in $InputObject.resourceSpecificApplicationPermissions) {
					$script:cache.ScopesByID[$scope.id] = $scope
				}
				#endregion Feed the Cache

				if ($Raw) { return $InputObject }

				[PSCustomObject]@{
					PSTypeName            = 'EntraAuth.Graph.ServicePrincipal'
					Type                  = $InputObject.servicePrincipalType
					Id                    = $InputObject.id
					AppID                 = $InputObject.AppID
					DisplayName           = $InputObject.DisplayName
					AppDisplayName        = $InputObject.AppDisplayName
					AppOwnerOrg           = $InputObject.AppOwnerOrganizationId
					AssignmentRequired    = $InputObject.appRoleAssignmentRequired
					ServicePrincipalNames = $InputObject.servicePrincipalNames

					Scopes                = @{
						Delegated   = @($InputObject.oauth2PermissionScopes)
						Application = @($InputObject.appRoles)
						AppResource = @($InputObject.resourceSpecificApplicationPermissions)
					}

					Object                = $InputObject
				}
			}
		}
	}
	process {
		$query = @{ }
		if ($Properties) {
			$query['$select'] = $Properties
		}
		if ($ObjectId) {
			try { Invoke-EntraRequest -Service $services.Graph -Path "servicePrincipals/$ObjectId" -Query $query | ConvertFrom-ServicePrincipal -Raw:$Raw }
			catch { $PSCmdlet.WriteError($_) }
			return
		}

		$filterBuilder = [FilterBuilder]::new()

		if ($DisplayName -and $DisplayName -ne '*') {
			$filterBuilder.Add('displayName', 'eq', $DisplayName)
		}
		if ($ApplicationId) {
			$filterBuilder.Add('appId', 'eq', $ApplicationId)
		}
		if ($Filter) {
			$filterBuilder.CustomFilter = $Filter
		}

		if ($filterBuilder.Count() -gt 0) {
			$query['$filter'] = $filterBuilder.Get()
		}
	
		Invoke-EntraRequest -Service $services.Graph -Path 'servicePrincipals' -Query $query | ConvertFrom-ServicePrincipal -Raw:$Raw
	}
}