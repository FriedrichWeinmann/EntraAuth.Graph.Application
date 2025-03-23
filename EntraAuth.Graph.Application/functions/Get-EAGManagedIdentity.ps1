function Get-EAGManagedIdentity {
	<#
	.SYNOPSIS
		Retrieves Managed Service Identities from Entra ID.

	.DESCRIPTION
		The Get-EAGManagedIdentity cmdlet retrieves Managed Service Identities (MSIs) from Entra ID.
		It allows you to search for MSIs by display name, application ID, or object ID, and filter the results.
		This cmdlet is a specialized wrapper around Get-EAGServicePrincipal that filters for service principals of type 'ManagedIdentity'.

		Scopes Needed: Application.Read.All

	.PARAMETER DisplayName
		The display name of the Managed Service Identity to retrieve.

	.PARAMETER ObjectId
		The Object ID of the Managed Service Identity to retrieve.
		When specified, returns a single MSI with the exact matching ID.

	.PARAMETER ApplicationId
		The Application ID (Client ID) of the Managed Service Identity to retrieve.
		Also known as AppId or ClientID.

	.PARAMETER Filter
		Additional OData filter expression to apply when searching for MSIs.

	.PARAMETER Properties
		Specific properties to retrieve from the MSI objects.

	.PARAMETER Raw
		When specified, returns the raw API response objects instead of the formatted PowerShell objects.
        Useful for accessing detailed properties not exposed at the top level, but less user-friendly.

	.PARAMETER ServiceMap
		Optional hashtable to map service names to specific EntraAuth service instances.
        Used for advanced scenarios where you want to use something other than the default Graph connection.
        Example: @{ Graph = 'GraphBeta' }
        This will switch all Graph API calls to use the beta Graph API.

	.EXAMPLE
		PS C:\> Get-EAGManagedIdentity

		Retrieves all Managed Service Identities in the Entra ID tenant.

	.EXAMPLE
		PS C:\> Get-EAGManagedIdentity -DisplayName "MyWebApp"

		Retrieves the Managed Service Identity with the display name "MyWebApp".

	.EXAMPLE
		PS C:\> Get-EAGManagedIdentity -ApplicationId "11111111-1111-1111-1111-111111111111"

		Retrieves the Managed Service Identity with the specified application ID.
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

		$param = @{ Filter = "servicePrincipalType eq 'ManagedIdentity'" }
		if ($DisplayName) { $param.DisplayName = $DisplayName }
		if ($ApplicationId) { $param.ApplicationId = $ApplicationId }
		if ($Filter) { $param.Filter = $param.Filter, $Filter -join ' and ' }

		Get-EAGServicePrincipal @common @param
	}
}
