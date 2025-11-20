function Add-EAGAppFederatedCredential {
	<#
	.SYNOPSIS
		Adds a Federated Credential to an App Registration.
	
	.DESCRIPTION
		Adds a Federated Credential to an App Registration.
		Federated Credentials allow authenticating as a Managed Identity directly, without having to manage any secrets.
		This means trusting the specified Issuer / Identity system instead.
	
	.PARAMETER ObjectId
		The ObjectID of the App Registration to add a Federated Credential to.
		
	.PARAMETER ApplicationId
		The ApplicationID (ClientID) of the App Registration to add a Federated Credential to.
	
	.PARAMETER Name
		Name of the Federated Credential to add.
		Must be unique on the App Registration.
	
	.PARAMETER Identity
		The Identity / Subject granted access to authenticate to the App Registration.
	
	.PARAMETER Issuer
		The issuing authority / identity system.
		Specifying a GUID will assume an Entra tenant ID is intended.
		Specifying nothing will instead use the Entra tenant ID of the current graph session.

		Is required in all non-Entra identity systems, such as Github pipelines.
	
	.PARAMETER Description
		Optional description to include with the Federated Credential.
	
	.PARAMETER Audiences
		The audience the Federated Credential is requested for.
		Defaults to "api://AzureADTokenExchange" and need not be changed in most situations.
	
	.PARAMETER AppCache
		A hashtable cache of App Registrations to optimize request performance.
		For each authentication method piped to this command, first the App Registration is looked up, if not in this cache.
		With this parameter, you can perform the caching across multiple separate invocations.
	
	.PARAMETER ServiceMap
		Optional hashtable to map service names to specific EntraAuth service instances.
        Used for advanced scenarios where you want to use something other than the default Graph connection.
        Example: @{ Graph = 'GraphBeta' }
        This will switch all Graph API calls to use the beta Graph API.

	.PARAMETER WhatIf
		If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.
	
	.PARAMETER Confirm
		If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.
	
	.EXAMPLE
		PS C:\> Add-EAGAppFederatedCredential -ApplicationID $appID -Name FunctionAppAccess -Identity $msiID -Issuer $tenantID

		Grants the Managed Identity in $msiID from tenant $tenantID access to the App $appID

	.EXAMPLE
		PS C:\> Get-EAGAppRegistration -DisplayName 'CAF-PS-BootcampDemo' | Add-EAGAppFederatedCredential -Name FunctionAppAccess -Identity 7613fc0d-6ca8-464e-ac86-fba8bfabf289 -Description "Grants function app Bootcamp-Function access"

		Adds a Federated Credential to the App Registration 'CAF-PS-BootcampDemo', granting the MSI 7613fc0d-6ca8-464e-ac86-fba8bfabf289 from the current tenant access.
	#>
	[CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'Identity')]
	param (
		[Parameter(Mandatory = $true, ParameterSetName = 'Identity', ValueFromPipelineByPropertyName = $true)]
		[Alias('Id')]
		[string]
		$ObjectId,

		[Parameter(Mandatory = $true, ParameterSetName = 'Filter', ValueFromPipelineByPropertyName = $true)]
		[Alias('AppId', 'ClientID')]
		[string]
		$ApplicationId,

		[Parameter(Mandatory = $true)]
		[string]
		$Name,

		[Parameter(Mandatory = $true)]
		[Alias('Subject')]
		[string]
		$Identity,

		[Alias('TenantID')]
		[string]
		$Issuer,

		[string]
		$Description,

		[string[]]
		$Audiences = @('api://AzureADTokenExchange'),

		[hashtable]
		$AppCache = @{ },

		[hashtable]
		$ServiceMap = @{}
	)
	begin {
		$services = $script:serviceSelector.GetServiceMap($ServiceMap)

		Assert-EntraConnection -Service $services.Graph -Cmdlet $PSCmdlet
	}
	process {
		#region Resolve App Registration to use
		$appResolved = Resolve-Application -ObjectId $ObjectId -ApplicationId $ApplicationId -Unique -Cache $AppCache -Services $services
		if (-not $appResolved.Success) {
			Invoke-NonTerminatingException -Cmdlet $PSCmdlet -Message $appResolved.Message -Category ObjectNotFound -Target "$($ApplicationId)$($ObjectId)"
			return
		}
		$currentApp = $appResolved.Result
		#endregion Resolve App Registration to use

		if (-not $Issuer -and -not ($Identity -as [guid])) {
			Invoke-TerminatingException -Cmdlet $PSCmdlet -Message "Unable to resolve identity/subject '$Identity' without specifying an issuer!" -Category InvalidData
		}

		$issuerName = $Issuer
		# Case: Entra MSI from a specified tenant
		if ($Issuer -as [guid] -and $Identity -as [guid]) { $issuerName = "https://login.microsoftonline.com/$Issuer/v2.0" }
		if (-not $Issuer) { $issuerName = "https://login.microsoftonline.com/$((Get-EntraToken -Service $services.Graph).TenantId)/v2.0" }
		$body = @{
			name      = $Name
			issuer    = $issuerName
			subject   = $Identity
			audiences = $Audiences
		}
		if ($Description) { $body.description = $Description }

		Write-Verbose "Adding Federated Credential '$($Name)' ($Identity) from '$issuerName' to App Registration '$($currentApp.DisplayName)' ($($currentApp.AppID))"
		if (-not $PSCmdlet.ShouldProcess("$($currentApp.DisplayName) ($($currentApp.AppID))", "Adding Federated Credential '$($Name)' ($Identity) from '$issuerName'")) { return }

		try { $result = Invoke-EntraRequest -Service $services.Graph -Method POST -Path "applications/$($currentApp.Id)/federatedIdentityCredentials" -Body $body -ContentType 'application/json' -WarningAction SilentlyContinue }
		catch {
			$PSCmdlet.WriteError($_)
			return
		}

		$authority = 'Unknown Authority'
		if ($result.issuer -eq 'https://token.actions.githubusercontent.com') { $authority = 'Github Actions' }
		elseif ($result.issuer -match '\.githubusercontent\.com$') { $authority = 'Github' }
		if ($result.issuer -like 'https://login.microsoftonline.com/*') { $authority = 'Microsoft Entra' }

		[PSCustomObject]@{
			PSTypeName = 'EntraAuth.Graph.Application.AppAuthentication'
			AppID      = $currentApp.AppID
			AppName    = $currentApp.DisplayName
			Type       = 'Federated'
			Name       = $result.Name
			Info       = '{0} | {1} | {2}' -f $authority, $result.subject, $result.description
			Identity   = $result.id
			Data       = $result
		}
	}
}