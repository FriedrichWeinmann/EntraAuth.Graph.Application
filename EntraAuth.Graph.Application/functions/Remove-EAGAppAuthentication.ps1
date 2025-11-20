function Remove-EAGAppAuthentication {
	<#
	.SYNOPSIS
		Removes authentication methods from an App Registration.
	
	.DESCRIPTION
		Removes authentication methods from an App Registration.
		Supports removal of Client Secrets, Client Certificates and Federated Credentials.
	
	.PARAMETER ObjectId
		The ObjectID of the App Registration to remove authentication methods from.
		
	.PARAMETER ApplicationId
		The ApplicationID (ClientID) of the App Registration to remove authentication methods from.
	
	.PARAMETER Identity
		The Identifier / keyId of the authentication method to remove.
	
	.PARAMETER Type
		What kind of authentication method the target to remove is.
	
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
		PS C:\> Get-EAGAppRegistration | Get-EAGAppAuthentication -Expired | Remove-EAGAppAuthentication

		Removes all expired authentication methods from all App Registrations in the tenant.
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

		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[Alias('keyId')]
		[string]
		$Identity,

		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[ValidateSet('Secret', 'Certificate', 'Federated')]
		[string]
		$Type,

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

		#region Perform Removal
		switch ($Type) {
			Secret {
				Write-Verbose "Removing Client Secret $($Identity) from App Registration '$($currentApp.DisplayName)' ($($currentApp.AppId))"
				if (-not $PSCmdlet.ShouldProcess("$($currentApp.DisplayName) ($($currentApp.AppId))", "Removing Client Secret $($Identity)")) { return }
				try { $null = Invoke-EntraRequest -Service $services.Graph -Method POST -Path "applications/$($currentApp.Id)/removePassword" -Body @{ keyId = $Identity } -ContentType 'application/json' -WarningAction SilentlyContinue }
				catch { Invoke-NonTerminatingException -Cmdlet $PSCmdlet -Message "Failed to remove Client Secret $($Identity) from App Registration '$($currentApp.DisplayName)' ($($currentApp.AppId)): $_" -ErrorRecord $_ }
			}
			Certificate {
				Write-Verbose "Removing Client Certificate $($Identity) from App Registration '$($currentApp.DisplayName)' ($($currentApp.AppId))"
				if (-not $PSCmdlet.ShouldProcess("$($currentApp.DisplayName) ($($currentApp.AppId))", "Removing Client Certificate $($Identity)")) { return }
				$appToPatch = Invoke-EntraRequest -Service $services.Graph -Path "applications/$($currentApp.Id)" -Raw -Query @{ '$select' = 'id', 'keyCredentials' }
				$newKeys = $appTopatch.keyCredentials | Where-Object keyId -NE $Identity

				try { $null = Invoke-EntraRequest -Service $services.Graph -Method PATCH -Path "applications/$($currentApp.Id)" -Body @{ keyCredentials = @($newKeys) } -ContentType 'application/json' -WarningAction SilentlyContinue }
				catch { Invoke-NonTerminatingException -Cmdlet $PSCmdlet -Message "Failed to remove Client Certificate $($Identity) from App Registration '$($currentApp.DisplayName)' ($($currentApp.AppId)): $_" -ErrorRecord $_ }
			}
			Federated {
				Write-Verbose "Removing Federated Credential $($Identity) from App Registration '$($currentApp.DisplayName)' ($($currentApp.AppId))"
				if (-not $PSCmdlet.ShouldProcess("$($currentApp.DisplayName) ($($currentApp.AppId))", "Removing Federated Credential $($Identity)")) { return }
				try { $null = Invoke-EntraRequest -Service $services.Graph -Method Delete -Path "applications/$($currentApp.Id)/federatedIdentityCredentials/$($Identity)" -WarningAction SilentlyContinue }
				catch { Invoke-NonTerminatingException -Cmdlet $PSCmdlet -Message "Failed to remove Federated Credential $($Identity) from App Registration '$($currentApp.DisplayName)' ($($currentApp.AppId)): $_" -ErrorRecord $_ }
			}
		}
		#endregion Perform Removal
	}
}