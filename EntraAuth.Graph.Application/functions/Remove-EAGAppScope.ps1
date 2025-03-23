function Remove-EAGAppScope {
	<#
	.SYNOPSIS
		Removes API permissions (scopes) from an App Registration.
	
	.DESCRIPTION
		Removes API permissions (scopes) from an App Registration.

		Scopes Needed: Application.Read.All, AppRoleAssignment.ReadWrite.All
	
	.PARAMETER DisplayName
		The display name of the App Registration to remove scopes from.
	
	.PARAMETER ApplicationId
		The Application ID (Client ID) of the App Registration to remove scopes from.
	
	.PARAMETER ObjectId
		The Object ID of the App Registration to remove scopes from.
	
	.PARAMETER Scope
		The permissions (scopes) to remove from the App Registration.
	
	.PARAMETER Type
		The type of the permissions to remove.
		Valid Options:
		- Delegated: Permissions that apply to interactive sessions, where the application acts on behalf of the signed-in user.
		- Application: Permissions that apply to unattended sessions, where the application acts as itself.
	
	.PARAMETER Resource
		The resource (API) to which the permissions/scopes apply.
        This can be specified as a display name, application ID, object ID or Service Principal Name.
        Examples:
        + 'Microsoft Graph'
        + '00000003-0000-0000-c000-000000000000'
        + 'https://graph.microsoft.com'
	
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
		PS C:\> Remove-EAGAppScope -DisplayName "MyWebApp" -Resource "Microsoft Graph" -Scope "User.Read.All" -Type Application

		Removes the User.Read.All application permission for Microsoft Graph from the App Registration named "MyWebApp".

	.EXAMPLE
		PS C:\> Get-EAGAppRegistration -DisplayName D-AAA-Task1 | Get-EAGScope | Remove-EAGAppScope

		Removes all scopes from the App Registration named "D-AAA-Task1".
	#>
	[CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'Filter')]
	param (
		[Parameter(ParameterSetName = 'Filter', ValueFromPipelineByPropertyName = $true)]
		[string]
		$DisplayName,

		[Parameter(ParameterSetName = 'Filter', ValueFromPipelineByPropertyName = $true)]
		[Alias('AppId', 'ClientID')]
		[string]
		$ApplicationId,

		[Parameter(Mandatory = $true, ParameterSetName = 'Identity', ValueFromPipelineByPropertyName = $true)]
		[Alias('Id')]
		[string]
		$ObjectId,

		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string[]]
		$Scope,

		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[ValidateSet('Delegated','Application')]
		[string]
		$Type,

		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string]
		$Resource,

		[hashtable]
		$ServiceMap
	)
	begin {
		$services = $script:serviceSelector.GetServiceMap($ServiceMap)

		Assert-EntraConnection -Service $services.Graph -Cmdlet $PSCmdlet

		$principals = @{ }
	}
	process {
		#region Resolve Scope Data
		$result = Resolve-ServicePrincipal -Identity $Resource -Cache $principals -Unique -Services $services
		if (-not $result.Success) {
			Write-Error -Message $result.Message
			return
		}
		$servicePrincipal = $result.Result
		
		$resolvedScopes = foreach ($entry in $Scope) {
			$scopeEntry = Resolve-Scope -Scope $entry -Resource $servicePrincipal.ID -Type $Type -Services $services
			if ($scopeEntry.ScopeName -eq '<not identified>') {
				Write-Error "Scope $entry of type $Type not found on Service Principal $($servicePrincipal.DisplayName) ($($servicePrincipal.ID) | $Resource)"
				continue
			}
			$scopeEntry
		}
		if (-not $resolvedScopes) {
			Write-Error -Message "No valid scopes found! Use 'Get-EAGScopeDefinition' to find the valid scopes for the resource and try again."
			return
		}
		#endregion Resolve Scope Data

		#region Resolve Application Data
		# Note: Can't cache, since previous process blocks might have affected the same object
		$result = Resolve-Application -DisplayName $DisplayName -ApplicationId $ApplicationId -ObjectId $ObjectId -Unique -Services $services
		if (-not $result.Success) {
			Write-Error $result.Message
			return
		}
		$application = $result.Result
		#endregion Resolve Application Data

		$body = @{
			requiredResourceAccess = @()
		}
		$newAccess = [PSCustomObject]@{
			resourceAppId = $servicePrincipal.AppId
			resourceAccess = @()
		}
		foreach ($access in $application.object.requiredResourceAccess) {
			if ($access.resourceAppId -ne $servicePrincipal.AppId) {
				$body.requiredResourceAccess += $access
				continue
			}

			foreach ($entry in $access.resourceAccess) {
				if ($entry.id -in $resolvedScopes.ID) { continue }
				$newAccess.resourceAccess += $entry
			}
		}
		if ($newAccess.resourceAccess.Count -gt 0) {
			$body.requiredResourceAccess += $newAccess
		}

		Write-Verbose ($body | ConvertTo-Json -Depth 99)

		if (-not $PSCmdlet.ShouldProcess($application.Id, "Removing scopes $($resolvedScopes.Value -join ', ')")) { return }

		try { $null = Invoke-EntraRequest -Method PATCH -Path "applications/$($application.Id)" -Body $body -Header @{ 'content-type' = 'application/json' } }
		catch {
			$PSCmdlet.WriteError($_)
			return
		}
	}
}