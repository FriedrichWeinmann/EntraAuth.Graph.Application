function Get-EAGEnterpriseApplication {
	<#
	.SYNOPSIS
		Retrieves Enterprise Applications from Entra ID.

	.DESCRIPTION
		Retrieves Enterprise Applications from Entra ID.

		Scopes Needed: Application.Read.All

	.PARAMETER DisplayName
		The display name of the Enterprise Application to retrieve.

	.PARAMETER ObjectId
		The Object ID of the Enterprise Application to retrieve.

	.PARAMETER ApplicationId
		The Application ID (Client ID) of the Enterprise Application to retrieve.
		Also known as AppId or ClientID.

	.PARAMETER Filter
		Additional OData filter expression to apply when searching for Enterprise Applications.

	.PARAMETER Properties
		Specific properties to retrieve from the Enterprise Application objects.

	.PARAMETER Raw
		When specified, returns the raw API response objects instead of the formatted PowerShell objects.
        Useful for accessing detailed properties not exposed at the top level, but less user-friendly.

	.PARAMETER ServiceMap
		Optional hashtable to map service names to specific EntraAuth service instances.
        Used for advanced scenarios where you want to use something other than the default Graph connection.
        Example: @{ Graph = 'GraphBeta' }
        This will switch all Graph API calls to use the beta Graph API.

	.EXAMPLE
		PS C:\> Get-EAGEnterpriseApplication

		Retrieves all Enterprise Applications in the Entra ID tenant.

	.EXAMPLE
		PS C:\> Get-EAGEnterpriseApplication -DisplayName "MyWebApp"

		Retrieves the Enterprise Applications  with the display name "MyWebApp".

	.EXAMPLE
		PS C:\> Get-EAGEnterpriseApplication -ApplicationId "11111111-1111-1111-1111-111111111111"

		Retrieves the Enterprise Applications  with the specified application ID.
	#>
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

		$param = @{ Filter = "servicePrincipalType eq 'Application'" }
		if ($DisplayName) { $param.DisplayName = $DisplayName }
		if ($ApplicationId) { $param.ApplicationId = $ApplicationId }
		if ($Filter) { $param.Filter = $param.Filter, $Filter -join ' and ' }

		Get-EAGServicePrincipal @common @param
	}
}