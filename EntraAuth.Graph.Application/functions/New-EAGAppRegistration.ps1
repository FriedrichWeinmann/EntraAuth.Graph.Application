function New-EAGAppRegistration {
	<#
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