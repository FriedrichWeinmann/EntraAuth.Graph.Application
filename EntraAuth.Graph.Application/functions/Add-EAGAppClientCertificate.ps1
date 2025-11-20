function Add-EAGAppClientCertificate {
	<#
	.SYNOPSIS
		Adds a client certificate to an App Registration.
	
	.DESCRIPTION
		Adds a client certificate to an App Registration.
	
	.PARAMETER ObjectId
		The ObjectID of the App Registration to add a client certificate to.
		
	.PARAMETER ApplicationId
		The ApplicationID (ClientID) of the App Registration to add a client certificate to.
	
	.PARAMETER Certificate
		The Certificate to add as a client certificate.
		Will only publish the public key.
	
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
		PS C:\> Add-EAGAppClientCertificate -ApplicationId bdcc7469-e495-451a-8618-4a57aace4b74 -Certificate $cert

		Adds the certificate in $cert as a client certificate to the specified application.

	.EXAMPLE
		PS C:\> Get-EAGAppRegistration -DisplayName 'CAF-PS-BootcampDemo' | Add-EAGAppClientCertificate -Certificate $cert

		Adds the certificate in $cert as a client certificate to the App Registration named 'CAF-PS-BootcampDemo'.
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
		[System.Security.Cryptography.X509Certificates.X509Certificate2]
		$Certificate,

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

		Write-Verbose "Adding Client Certificate '$($Certificate.Subject)' to App Registration '$($currentApp.DisplayName)' ($($currentApp.AppID))"
		if (-not $PSCmdlet.ShouldProcess("$($currentApp.DisplayName) ($($currentApp.AppID))", "Adding Client Certificate '$($Certificate.Subject)'")) { return }

		$newKey = @{
			customKeyIdentifier = $Certificate.Thumbprint
			displayName         = $Certificate.Subject
			endDateTime         = $Certificate.NotAfter.ToUniversalTime().ToString('u') -replace ' ', 'T'
			key                 = [Convert]::ToBase64String($Certificate.GetRawCertData())
			startDateTime       = $Certificate.NotBefore.ToUniversalTime().ToString('u') -replace ' ', 'T'
			type                = 'AsymmetricX509Cert'
			usage               = 'Verify'
		}

		$appToPatch = Invoke-EntraRequest -Service $services.Graph -Path "applications/$($currentApp.Id)" -Raw -Query @{ '$select' = 'id', 'keyCredentials' }
		$matchingKeys = $appTopatch.keyCredentials | Where-Object {
			$_.customKeyIdentifier -eq $newKey.customKeyIdentifier -and
			$_.displayName -eq $newKey.displayName -and
			$_.startDateTime -eq $Certificate.NotBefore.ToUniversalTime() -and
			$_.endDateTime -eq $Certificate.NotAfter.ToUniversalTime()
		}
		if ($matchingKeys) {
			Write-Verbose "Client Certificate '$($Certificate.Subject)' already exists on App Registration '$($currentApp.DisplayName)' ($($currentApp.AppID))"
			return
		}
		$newKeys = @($appTopatch.keyCredentials) + $newKey

		try { $null = Invoke-EntraRequest -Service $services.Graph -Method PATCH -Path "applications/$($currentApp.Id)" -Body @{ keyCredentials = @($newKeys) } -ContentType 'application/json' -WarningAction SilentlyContinue }
		catch { Invoke-NonTerminatingException -Cmdlet $PSCmdlet -Message "Failed to add Client Certificate $($Certificate.Subject) to App Registration '$($currentApp.DisplayName)' ($($currentApp.AppId)): $_" -ErrorRecord $_ }
	}
}