function Get-EAGScopeDefinition {
	<#
	.SYNOPSIS
		Retrieves scope definitions from service principals / Enterprise applications.
	
	.DESCRIPTION
		Retrieves scope definitions from service principals / Enterprise applications.
		This does NOT return assigned or granted scopes on the apps.
		It provides the scopes provided BY the service in question.
	
	.PARAMETER Name
		The name of the scope to filter by.
	
	.PARAMETER Type
		The type of scopes to retrieve.
		Valid Options:
		- All: All scopes (default)
		- Delegated: Delegated scopes
		- Application: Application scopes
		- AppResource: Resource-specific Application  scopes
	
	.PARAMETER DisplayName
		Filter by display name of the service principal.
	
	.PARAMETER ApplicationId
		Filter by application ID of the service principal.
	
	.PARAMETER ObjectId
		Filter by object ID of the service principal.
	
	.PARAMETER Resource
		Filter by the resource Identifier of the service.
	
	.PARAMETER Force
		Include disabled scopes.
	
	.PARAMETER ServiceMap
		Optional hashtable to map service names to specific EntraAuth service instances.
        Used for advanced scenarios where you want to use something other than the default Graph connection.
        Example: @{ Graph = 'GraphBeta' }
        This will switch all Graph API calls to use the beta Graph API.
	
	.EXAMPLE
		PS C:\> Get-EAGScopeDefinition -Name "User.Read"
	
		Retrieves all scopes with the name "User.Read".

	.EXAMPLE
		PS C:\> Get-EAGScopeDefinition -DisplayName 'Microsoft Graph'
	
		Retrieves all scopes provided by the service principal with the display name 'Microsoft Graph'.

	.EXAMPLE
		PS C:\> Get-EAGScopeDefinition -DisplayName 'Microsoft Graph' -Name User.*

		Retrieves all scopes with the name starting with 'User.' provided by the service principal with the display name 'Microsoft Graph'.

	.EXAMPLE
		PS C:\> Get-EAGScopeDefinition -Resource https://graph.microsoft.com -Name Group.*

		Retrieves all scopes with the name starting with 'Group.' provided by the service principal with the service principal name 'https://graph.microsoft.com'.
	#>
	[CmdletBinding(DefaultParameterSetName = 'Filter')]
	param (
		[string]
		$Name = '*',

		[ValidateSet('All', 'Delegated', 'Application', 'AppResource')]
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

		[Parameter(Mandatory = $true, ParameterSetName = 'Resource')]
		[string]
		$Resource,

		[switch]
		$Force,

		[hashtable]
		$ServiceMap = @{}
	)
	begin {
		$services = $script:serviceSelector.GetServiceMap($ServiceMap)

		Assert-EntraConnection -Service $services.Graph -Cmdlet $PSCmdlet

		function New-ScopeDefinition {
			[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseShouldProcessForStateChangingFunctions", "")]
			[CmdletBinding()]
			param (
				[string]
				$ResourceID,
				[string]
				$ResourceName,
				[string]
				$Type,
				[string]
				$ScopeID,
				[string]
				$ScopeName,
				[string]
				$Description,
				[bool]
				$Consent = $true,
				[bool]
				$Enabled,

				$Object
			)

			if ($Object) {
				$Enabled = $Object.isEnabled
				$ScopeID = $Object.id
				$ScopeName = $Object.value
			}

			[PSCustomObject]@{
				PSTypeName      = 'EntraAuth.Graph.ScopeDefinition'
				ResourceID      = $ResourceID
				ResourceName    = $ResourceName
				Type            = $Type
				ScopeID         = $ScopeID
				ScopeName       = $ScopeName
				Description     = $Description
				ConsentRequired = $Consent
				Enabled         = $Enabled
			}
		}
	}
	process {
		$param = @{}
		if ($DisplayName) { $param.DisplayName = $DisplayName }
		if ($ApplicationId) { $param.ApplicationId = $ApplicationId }
		if ($ObjectId) { $param.ObjectId = $ObjectId }
		if ($Resource) {
			$filter = "serviceprincipalNames/any(x:x eq '$Resource')"
			if ($Resource -as [guid]) {
				$filter = "id eq '$Resource' or appId eq '$Resource' or serviceprincipalNames/any(x:x eq '$Resource')"
			}
			$param.Filter = $filter
		}

		$servicePrincipals = Get-EAGServicePrincipal @param -Properties id, appid, displayName, servicePrincipalType, appRoles, oauth2PermissionScopes, resourceSpecificApplicationPermissions -ServiceMap $ServiceMap

		foreach ($servicePrincipal in $servicePrincipals) {
			$spnData = @{ ResourceID = $servicePrincipal.ID; ResourceName = $servicePrincipal.displayName }

			if ($Type -in 'All', 'Delegated') {
				foreach ($scope in $servicePrincipal.Scopes.Delegated) {
					if (-not $scope.isEnabled -and -not $Force) { continue }
					if ($scope.value -notlike $Name) { continue }
					New-ScopeDefinition @spnData -Object $scope -Type Delegated -Description $scope.adminConsentDescription -Consent ($scope.type -eq 'Admin')
				}
			}
			if ($Type -in 'All', 'Application') {
				foreach ($scope in $servicePrincipal.Scopes.Application) {
					if (-not $scope.isEnabled -and -not $Force) { continue }
					if ($scope.value -notlike $Name) { continue }
					New-ScopeDefinition @spnData -Object $scope -Type Application -Description $scope.description
				}
			}
			if ($Type -in 'All', 'AppResource') {
				foreach ($scope in $servicePrincipal.Scopes.AppResource) {
					if (-not $scope.isEnabled -and -not $Force) { continue }
					if ($scope.value -notlike $Name) { continue }
					New-ScopeDefinition @spnData -Object $scope -Type AppResource -Description $scope.description
				}
			}
		}
	}
}