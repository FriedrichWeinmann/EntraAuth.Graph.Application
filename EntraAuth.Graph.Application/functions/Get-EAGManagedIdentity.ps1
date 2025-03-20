function Get-EAGManagedIdentity {
	[CmdletBinding(DefaultParameterSetName = 'Filter')]
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
		$common = @{ ServiceMap = $services }
		if ($Properties) { $common.Properties = $Properties }
		if ($Raw) { $common.Raw = $Raw }

		if ($ObjectID) {
			Get-EAGServicePrincipal @common -ObjectId $ObjectId
			return
		}

		$param = @{ Filter = "servicePrincipalType eq 'ManagedIdentity'" }
		if ($DisplayName) { $param.DisplayName = $DisplayName }
		if ($ApplicationId) { $param.ApplicationId = $ApplicationId }
		if ($Filter) { $param.Filter = $param.Filter, $Filter -join ' and ' }

		Get-EAGServicePrincipal @common @param
	}
}