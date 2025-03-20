function Resolve-ScopePrincipal {
	[CmdletBinding()]
	param (
		[AllowNull()]
		[string]
		$ID,

		[hashtable]
		$Services
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