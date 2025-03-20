function Get-EAGScopeDefinition {
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