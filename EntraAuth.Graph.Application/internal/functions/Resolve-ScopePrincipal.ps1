function Resolve-ScopePrincipal {
	<#
	.SYNOPSIS
		Resolves the identity of a user that consented to a scope.
	
	.DESCRIPTION
		Resolves the identity of a user that consented to a scope.
		These identities are cached for performance reasons.

		Scopes Needed: User.ReadBasic.All (Delegated), User.Read.All (Application)
	
	.PARAMETER ID
		The ObjectID of the user to resolve.
	
	.PARAMETER Services
		A hashtable mapping which EntraAuth service should be called for Graph requests.
		Example: @{ Graph = 'GraphBeta' }
		Generally, this parameter should receive a passed through -ServiceMap parameter from a public command.
	
	.EXAMPLE
		PS C:\> Resolve-ScopePrincipal -ID "11111111-1111-1111-1111-111111111111"
		
		Resolves the user with the ObjectID "11111111-1111-1111-1111-111111111111".
	#>
	[CmdletBinding()]
	param (
		[AllowNull()]
		[string]
		$ID,

		[hashtable]
		$Services = @{}
	)
	process {
		if (-not $ID) {
			[PSCustomObject]@{
				Name = ''
				ID = ''
			}
			return
		}
		if ($script:cache.Principals[$ID]) { return $script:cache.Principals[$ID] }

		try {
			$user = Invoke-EntraRequest -Service $Services.Graph -Path "users/$ID" -Query @{
				'$select' = 'id', 'displayName'
			} -WarningAction SilentlyContinue -ErrorAction Stop

			$script:cache.Principals[$ID] = [PSCustomObject]@{
				Name = $user.displayName
				ID = $user.id
			}
		}
		catch {
			$script:cache.Principals[$ID] = [PSCustomObject]@{
				Name = ''
				ID = $ID
			}
		}
		$script:cache.Principals[$ID]
	}
}