# Graph Request Configuration
$script:_services = @{
	Graph = 'Graph'
	GraphBeta = 'GraphBeta'
	KeyVault = 'AzureKeyVault'
}
$script:serviceSelector = [ServiceSelector]::new()

# Caches for frequent lookups
$script:cache = @{
	ServicePrincipalByAppID = @{}
	ServicePrincipalByID = @{}
	ScopesByID = @{}
	ResolvedScopes = @{}
	Principals = @{}
}