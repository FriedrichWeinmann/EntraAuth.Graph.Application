function Get-EAGAppRegistration {
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