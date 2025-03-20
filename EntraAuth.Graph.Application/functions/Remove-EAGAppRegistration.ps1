function Remove-EAGAppRegistration {
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