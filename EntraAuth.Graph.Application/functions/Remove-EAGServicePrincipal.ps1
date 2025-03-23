function Remove-EAGServicePrincipal {
	<#
	.SYNOPSIS
		Deletes Enterprise Applications / service principals from the connected Entra ID tenant.
	
	.DESCRIPTION
		Deletes Enterprise Applications / service principals from the connected Entra ID tenant.

		Scopes Needed: Application.ReadWrite.All
			
	.PARAMETER Id
		Object ID of the service principal to delete.
	
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
		PS C:\> Get-EAGServicePrincipal -DisplayName "MyWebApp" | Remove-EAGServicePrincipal
	
		Deletes the service principal with the display name "MyWebApp".
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
			if (-not $PSCmdlet.ShouldProcess($entry, "Delete Service Principal")) { continue }
			try { Invoke-EntraRequest -Service $services.Graph -Method DELETE -Path "servicePrincipals/$entry" }
			catch {
				$PSCmdlet.WriteError($_)
				continue
			}
		}
	}
}