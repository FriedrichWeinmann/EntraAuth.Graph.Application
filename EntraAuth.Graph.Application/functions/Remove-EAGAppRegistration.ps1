function Remove-EAGAppRegistration {
	<#
	.SYNOPSIS
		Murders innocent App Registrations.
	
	.DESCRIPTION
		Murders innocent App Registrations.
		They will be gone, forever.
		Rest in Pieces.

		Scopes Needed: Application.ReadWrite.All
	
	.PARAMETER Id
		Object ID of the app registration to slaughter.
	
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
		PS C:\> Get-EAGAppRegistration -DisplayName "MyWebApp" | Remove-EAGAppRegistration

		Deletes the app registration with the display name "MyWebApp".
	#>
	[CmdletBinding(SupportsShouldProcess = $true)]
	param (
		[Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[string[]]
		$Id,

		[hashtable]
		$ServiceMap = @{}
	)

	begin {
		$services = $script:serviceSelector.GetServiceMap($ServiceMap)

		Assert-EntraConnection -Service $services.Graph -Cmdlet $PSCmdlet
	}
	process {
		foreach ($entry in $Id) {
			if (-not $PSCmdlet.ShouldProcess($entry, "Delete App Registration")) { continue }
			try { Invoke-EntraRequest -Service $services.Graph -Method DELETE -Path "applications/$entry" }
			catch {
				$PSCmdlet.WriteError($_)
				continue
			}
		}
	}
}