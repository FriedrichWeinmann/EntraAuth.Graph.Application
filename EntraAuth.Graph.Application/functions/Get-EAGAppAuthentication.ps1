function Get-EAGAppAuthentication {
	<#
	.SYNOPSIS
		List App Registration authentication settings / options.
	
	.DESCRIPTION
		List App Registration authentication settings / options.
		This includes secrets, certificates and federated credentials.
	
	.PARAMETER DisplayName
		The displayname of the app registration to scan.
	
	.PARAMETER ObjectId
		The object ID of the app registration to scan.
	
	.PARAMETER ApplicationId
		The application ID of the app registration to scan.
	
	.PARAMETER Filter
		Additional OData filter expression to apply when searching for app registrations to scan.
	
	.PARAMETER Type
		What kind of secrets to retrieve.

	.PARAMETER Expired
		Only show expired authentication options.
	
	.PARAMETER ServiceMap
		Optional hashtable to map service names to specific EntraAuth service instances.
        Used for advanced scenarios where you want to use something other than the default Graph connection.
        Example: @{ Graph = 'GraphBeta' }
        This will switch all Graph API calls to use the beta Graph API.
	
	.EXAMPLE
		PS C:\> Get-EAGAppAuthentication

		List all registered app authentication settings for all App Registrations in the tenant

	.EXAMPLE
		PS C:\> Get-EAGAppAuthentication -DisplayName CAF-PS-BootcampDemo

		List all registered app authentication settings for the App Registration "CAF-PS-BootcampDemo"
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

		[ValidateSet('Secret', 'Certificate', 'Federated')]
		[string[]]
		$Type,

		[switch]
		$Expired,

		[hashtable]
		$ServiceMap = @{}
	)
	begin {
		$services = $script:serviceSelector.GetServiceMap($ServiceMap)

		Assert-EntraConnection -Service $services.Graph -Cmdlet $PSCmdlet

		$appsProcessed = @{}

		$doProcess = @{
			Secret      = -not $Type -or $Type -contains 'Secret'
			Certificate = -not $Type -or $Type -contains 'Certificate'
			Federated   = (-not $Type -or $Type -contains 'Federated') -and (-not $Expired)
		}
	}
	process {
		$param = @{}
		if ($DisplayName) { $param.DisplayName = $DisplayName }
		if ($ObjectId) { $param.ObjectId = $ObjectId }
		if ($ApplicationId) { $param.ApplicationId = $ApplicationId }
		if ($Filter) { $param.Filter = $Filter }
		$applications = Get-EAGAppRegistration -ServiceMap $services @param | Where-Object { -not $appsProcessed[$_.Id] }

		$pairs = Invoke-EagBatchRequest -Path 'applications/{0}/federatedIdentityCredentials' -ArgumentList $applications -Properties Id -Matched -ServiceMap $services

		foreach ($pair in $pairs) {
			$appsProcessed[$pair.Argument.Id] = $true

			#region Process Client Secrets
			if ($doProcess.Secret) {
				foreach ($secret in $pair.Argument.Object.passwordCredentials) {
					if ($Expired -and ($secret.endDateTime -gt (Get-Date))) { continue }

					[PSCustomObject]@{
						PSTypeName = 'EntraAuth.Graph.Application.AppAuthentication'
						AppID      = $pair.Argument.AppID
						AppName    = $pair.Argument.DisplayName
						Type       = 'Secret'
						Name       = $secret.displayName
						Info       = '{0:yyyy-MM-dd HH:mm:ss} -> {1:yyyy-MM-dd HH:mm:ss}' -f $secret.startDateTime, $secret.endDateTime
						Identity   = $secret.keyId
						Data       = $secret
					}
				}
			}
			#endregion Process Client Secrets

			#region Process Client Certificates
			if ($doProcess.Certificate) {
				foreach ($cert in $pair.Argument.Object.keyCredentials) {
					if ($Expired -and ($cert.endDateTime -gt (Get-Date))) { continue }

					[PSCustomObject]@{
						PSTypeName = 'EntraAuth.Graph.Application.AppAuthentication'
						AppID      = $pair.Argument.AppID
						AppName    = $pair.Argument.DisplayName
						Type       = 'Certificate'
						Name       = $cert.displayName
						Info       = '{0:yyyy-MM-dd HH:mm:ss} -> {1:yyyy-MM-dd HH:mm:ss}' -f $cert.startDateTime, $cert.endDateTime
						Identity   = $cert.keyId
						Data       = $cert
					}
				}
			}
			#endregion Process Client Certificates

			#region Federated Credential
			if ($doProcess.Federated) {
				foreach ($federated in $pair.Result) {
					$authority = 'Unknown Authority'
					if ($federated.issuer -eq 'https://token.actions.githubusercontent.com') { $authority = 'Github Actions' }
					elseif ($federated.issuer -match '\.githubusercontent\.com$') { $authority = 'Github' }
					if ($federated.issuer -like 'https://login.microsoftonline.com/*') { $authority = 'Microsoft Entra' }

					[PSCustomObject]@{
						PSTypeName = 'EntraAuth.Graph.Application.AppAuthentication'
						AppID      = $pair.Argument.AppID
						AppName    = $pair.Argument.DisplayName
						Type       = 'Federated'
						Name       = $federated.Name
						Info       = '{0} | {1} | {2}' -f $authority, $federated.subject, $federated.description
						Identity   = $federated.id
						Data       = $federated
					}
				}
			}
			#endregion Federated Credential
		}
	}
}