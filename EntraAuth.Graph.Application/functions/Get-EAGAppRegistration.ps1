function Get-EAGAppRegistration {
	<#
	.SYNOPSIS
		Lists application registrations in the connected Entra ID tenant.
	
	.DESCRIPTION
		Lists application registrations in the connected Entra ID tenant.
		You can filter the results by display name, application ID, or custom filter.

		Scopes Needed: Application.Read.All
	
	.PARAMETER DisplayName
		Display name of the app registration to retrieve.
	
	.PARAMETER ObjectId
		Object ID of the app registration to retrieve.
	
	.PARAMETER ApplicationId
		Application ID (Client ID) of the app registration to retrieve.
	
	.PARAMETER Filter
		Additional OData filter expression to apply when searching for app registrations.
	
	.PARAMETER Properties
		Specific properties to retrieve from the app registration objects.
	
	.PARAMETER Raw
		When specified, returns the raw API response objects instead of the formatted PowerShell objects.
        Useful for accessing detailed properties not exposed at the top level, but less user-friendly.
	
	.PARAMETER ServiceMap
		Optional hashtable to map service names to specific EntraAuth service instances.
        Used for advanced scenarios where you want to use something other than the default Graph connection.
        Example: @{ Graph = 'GraphBeta' }
        This will switch all Graph API calls to use the beta Graph API.
	
	.EXAMPLE
		PS C:\> Get-EAGAppRegistration
	
		Retrieves all app registrations in the Entra ID tenant.

	.EXAMPLE
		PS C:\> Get-EAGAppRegistration -DisplayName "MyWebApp"
	
		Retrieves the app registration with the display name "MyWebApp".

	.EXAMPLE
		PS C:\> Get-EAGAppRegistration -DisplayName 'Dept-*' -Properties 'displayName', 'appId'
	
		Retrieves all app registrations that start with "Dept-" and returns only the display name and app ID properties.
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
	}
	process {
		$query = @{ }
		if ($Properties) {
			$query['$select'] = $Properties
		}
		if ($ObjectId) {
			try { Invoke-EntraRequest -Service $services.Graph -Path "applications/$ObjectId" -Query $query | ConvertFrom-Application -Raw:$Raw }
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
	
		Invoke-EntraRequest -Service $services.Graph -Path 'applications' -Query $query | ConvertFrom-Application -Raw:$Raw
	}
}