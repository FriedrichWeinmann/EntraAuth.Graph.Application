function ConvertFrom-Application {
	<#
	.SYNOPSIS
		Converts raw App Registration objects from the Graph API to a more user-friendly format.
	
	.DESCRIPTION
		Converts raw App Registration objects from the Graph API to a more user-friendly format.
	
	.PARAMETER InputObject
		The raw App Registration object to convert.
	
	.PARAMETER Raw
		Actually, don't convert the object after all.
	
	.EXAMPLE
		PS C:\> Invoke-EntraRequest -Path "applications/$ObjectId" | ConvertFrom-Application

		Converts the raw App Registration object to a more user-friendly format.
	#>
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