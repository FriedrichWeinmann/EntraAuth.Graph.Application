function Remove-EAGServicePrincipal {
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