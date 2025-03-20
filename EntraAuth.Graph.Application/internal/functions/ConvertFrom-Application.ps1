function ConvertFrom-Application {
	[CmdletBinding()]
	param (
		[Parameter(ValueFromPipeline = $true)]
		$InputObject,

		[switch]
		$Raw
	)

	begin {
		$scopeTypeMap = @{
			$true  = 'Delegated'
			$false = 'Application'
		}
	}
	process {
		if ($Raw) { return $InputObject }

		$scopes = foreach ($resource in $InputObject.requiredResourceAccess) {
			foreach ($access in $resource.resourceAccess) {
				[PSCustomObject]@{
					PSTypeName      = 'EntraAuth.Graph.Scope'
					ApplicationId   = $InputObject.appId
					ApplicationName = $InputObject.DisplayName
					Resource        = $resource.resourceAppId
					ResourceName    = $script:cache.ServicePrincipalByAppID."$($resource.resourceAppId)".displayName
					Type            = $scopeTypeMap[($access.type -eq 'Scope')]
					Scope           = $access.id
					ScopeName       = $script:cache.ScopesByID."$($access.id)".value
					ConsentRequired = $null
					HasConsent      = $null
					PrincipalName   = $null
					PrincipalID     = $null
				}
			}
		}

		[PSCustomObject]@{
			PSTypeName  = 'EntraAuth.Graph.Application'
			Id          = $InputObject.id
			AppID       = $InputObject.AppID
			DisplayName = $InputObject.DisplayName

			Scopes      = $scopes

			Object      = $InputObject
		}
	}
}