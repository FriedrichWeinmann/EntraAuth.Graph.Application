function New-EAGAppRegistration {
	<#
	.SYNOPSIS
		Creates a new App Registration in the connected Entra ID tenant.
	
	.DESCRIPTION
		Creates a new App Registration in the connected Entra ID tenant.
		By default, it will also create the associated Enterprise Application (service principal).

		Scopes Needed: Application.ReadWrite.All
	
	.PARAMETER DisplayName
		The display name of the App Registration.
	
	.PARAMETER Description
		The description of the App Registration.
	
	.PARAMETER RedirectUri
		Any redirect URIs to associate with the App Registration.
		These are needed for Delegated authentication flows, where the application acts on behalf of a user.
	
	.PARAMETER Platform
		When specifying a RedirectUri, what "Platform" should be configured.
		This determines, how authentication can be performed.
		Options:
		- MobileDesktop: This will enable the authentication, where a browser window pops up and asks the user to authenticate. (Authorization Code flow)
		- Web: This will enable the authentication, where the user is asked to open a specific URL and paste in a code provided, THEN authenticate. (DeviceCode flow)
		Generally, MobileDesktop is the preferred option, as it is more user-friendly and secure.
		Defaults to: MobileDesktop
	
	.PARAMETER NoEnterpriseApp
		Do not create the associated Enterprise Application (service principal).
		By default, the Enterprise Application is created automatically, as without it, the App Registration cannot really be used.
	
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
		PS C:\> New-EAGAppRegistration -DisplayName "DEPT-AAA-Task1" -RedirectUri "http://Localhost"
	
		Creates a new App Registration named "DEPT-AAA-Task1" with the redirect URI "http://Localhost".
		This could then be used to authenticate to interactively from PowerShell.

	.LINK
		https://learn.microsoft.com/en-us/graph/api/application-post-applications?view=graph-rest-1.0&tabs=http
	#>
	[CmdletBinding(SupportsShouldProcess = $true)]
	param (
		[Parameter(Mandatory = $true)]
		[string]
		$DisplayName,

		[string]
		$Description,

		[string[]]
		$RedirectUri,

		[ValidateSet('MobileDesktop', 'Web')]
		[string]
		$Platform = 'MobileDesktop',

		[switch]
		$NoEnterpriseApp,

		[hashtable]
		$ServiceMap = @{}
	)

	begin {
		$services = $script:serviceSelector.GetServiceMap($ServiceMap)

		Assert-EntraConnection -Service $services.Graph -Cmdlet $PSCmdlet
	}
	process {
		$body = @{
			displayName = $DisplayName
		}
		if ($RedirectUri) {
			switch ($Platform) {
				MobileDesktop {
					$body["publicClient"] = @{
						redirectUris = @($RedirectUri)
					}
				}
				Web {
					$body["web"] = @{
						redirectUris = @($RedirectUri)
					}
				}
				default {
					Invoke-TerminatingException -Message "Platform not implemented yet: $Platform" -Cmdlet $PSCmdlet -Category NotImplemented
				}
			}
		}
		if ($Description) { $Body.description = $Description }

		Write-Verbose "Final Request Body:`n$($body | ConvertTo-Json)"

		if (-not $PSCmdlet.ShouldProcess($DisplayName, "Create App Registration")) { return }

		$appRegistration = Invoke-EntraRequest -Service $services.Graph -Method POST -Path applications -Body $body -Header @{ 'content-type' = 'application/json' }
		$appRegistration | ConvertFrom-Application
		if ($NoEnterpriseApp) { return }

		$null = Invoke-EntraRequest -Service $services.Graph -Method POST -Path servicePrincipals -Body @{
			appId = $appRegistration.appId
		} -Header @{ 'content-type' = 'application/json' }
	}
}