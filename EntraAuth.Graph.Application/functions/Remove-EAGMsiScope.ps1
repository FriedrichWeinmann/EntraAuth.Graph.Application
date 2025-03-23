function Remove-EAGMsiScope {
	<#
	.SYNOPSIS
		Removes API permissions (scopes) from a Managed Service Identity.

	.DESCRIPTION
		The Remove-EAGMsiScope cmdlet removes application permissions (scopes) from a Managed Service Identity (MSI).
		This is useful when you need to revoke access to specific APIs or reduce the permissions of an MSI.

		Scopes Needed: Application.Read.All, AppRoleAssignment.ReadWrite.All

	.PARAMETER DisplayName
		The display name of the Managed Service Identity to remove permissions from.

	.PARAMETER ApplicationId
		The Application ID (Client ID) of the Managed Service Identity to remove permissions from.

	.PARAMETER ObjectId
		The Object ID of the Managed Service Identity to remove permissions from.

	.PARAMETER Scope
		The permission scopes to remove from the Managed Service Identity.
		These are the API permissions that will be revoked.

	.PARAMETER Resource
		The resource (API) to which the permissions/scopes apply.
        This can be specified as a display name, application ID, object ID or Service Principal Name.
        Examples:
        + 'Microsoft Graph'
        + '00000003-0000-0000-c000-000000000000'
        + 'https://graph.microsoft.com'

	.PARAMETER ServiceMap
		%SERVCICEMAP%

	.PARAMETER WhatIf
		If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.
	
	.PARAMETER Confirm
		If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.

	.EXAMPLE
		PS C:\> Remove-EAGMsiScope -DisplayName "MyWebApp" -Resource "Microsoft Graph" -Scope "User.Read.All"

		Removes the User.Read.All application permission for Microsoft Graph from the MSI named "MyWebApp".

	.EXAMPLE
		PS C:\> Remove-EAGMsiScope -ApplicationId "11111111-1111-1111-1111-111111111111" -Resource "00000003-0000-0000-c000-000000000000" -Scope "User.Read.All", "Group.Read.All"

		Removes the User.Read.All and Group.Read.All application permissions for Microsoft Graph (identified by its app ID) from the MSI with the specified application ID.
	#>
	[CmdletBinding(DefaultParameterSetName = 'Filter', SupportsShouldProcess = $true)]
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
		[string]
		$Resource,

		[hashtable]
		$ServiceMap
	)
	begin {
		$services = $script:serviceSelector.GetServiceMap($ServiceMap)

		Assert-EntraConnection -Service $services.Graph -Cmdlet $PSCmdlet

		$principals = @{ }
		$servicePrincipals = @{}
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
			$scopeEntry = Resolve-Scope -Scope $entry -Resource $servicePrincipal.ID -Type 'Application' -Services $services
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
		$identity = $ObjectId
		if (-not $identity) { $identity = $ApplicationId }
		if (-not $identity) { $identity = $DisplayName }
		if (-not $identity) {
			Write-Error -Message "Managed Identity not specified! Provide at least one of ObjectId, ApplicationId or DisplayName."
			return
		}
		$result = Resolve-ServicePrincipal -Identity $identity -Properties id, appId, displayName -Cache $servicePrincipals -Unique -Services $services
		if (-not $result.Success) {
			Write-Error "Error resolving Managed Identity for $($identity):`n$($result.Message)"
			return
		}
		$appSPN = $result.Result
		#endregion Resolve Application Data

		$applicationGrants = Invoke-EntraRequest -Service $services.Graph -Path "servicePrincipals/$($appSPN.id)/appRoleAssignments"

		foreach ($resolvedScope in $resolvedScopes) {
			if ($resolvedScope.ID -notin $applicationGrants.appRoleId) {
				Write-Verbose "Skipping Application scope $($resolvedScope.Value) - not found on $($appSPN.DisplayName)"
				continue
			}

			if (-not $PSCmdlet.ShouldProcess("$($appSPN.DisplayName) ($($appSPN.AppID))", "Removing scope $($resolvedScope.Value) of resource $($resolvedScope.ResourceName)")) {
				continue
			}

			Write-Verbose "Processing scope:`n$($resolvedScope | ConvertTo-Json)"
			$grantToKill = $applicationGrants | Where-Object appRoleId -EQ $resolvedScope.ID

			Write-Verbose "Removing scope $($resolvedScope.id) ($($resolvedScope.Value))) from Managed Identity $($appSPN.appid) ($($appSPN.displayName))"
			try {
				$null = Invoke-EntraRequest -Method DELETE -Path "servicePrincipals/$($appSPN.id)/appRoleAssignments/$($grantToKill.id)" -Header @{
					'content-type' = 'application/json'
				}
			}
			catch {
				Write-Error $_
			}
		}
	}
}
