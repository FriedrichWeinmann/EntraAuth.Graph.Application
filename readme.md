# EntraAuth.Graph.Application

Welcome to the PowerShell module designed to bring the convenience of the Entra Portal to your PowerShell Console.
At least when creating and managing App Registrations or managing scopes (whether adding them to an App Registration, granting consent or adding them to a Managed Identity. Or undoing all that).

## Installation

To get started with this, install the module from the PowerShell Galelry:

```powershell
Install-Module EntraAuth.Graph.Application -Scope CurrentUser
```

## Authenticating

This module relies on [EntraAuth](https://github.com/FriedrichWeinmann/EntraAuth) for authentication.
Commonly needed scopes are `Application.Read.All` or `Application.ReadWrite.All` for interacting with App Registrations and Enterprise Applications themselves, `AppRoleAssignment.ReadWrite.All` for modifying scopes.

Example connect:

```powershell
Connect-EntraService -ClientID Graph -Scopes 'Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All'
```

For guidance on how to set up your own "Application" and configuring API access, see [this guidance to setting it all up.](https://github.com/FriedrichWeinmann/EntraAuth/blob/master/docs/overview.md)
For more examples on how to connect, [visit the EntraAuth site and scroll down](https://github.com/FriedrichWeinmann/EntraAuth).

The description on each command in this module has the exact list of scopes needed (always listing the least privileged scope).

## Profit

With that we are ready to roll.
A few examples:

```powershell
# Create a new App Registration (and its Enterprise App)
New-EAGAppRegistration -DisplayName MyDemoApp

# Assign scopes and consent them
Add-EAGAppScope -DisplayName MyDemoApp -Scope User.ReadBasic.All, Group.Read.All, Mail.Send -Type Delegated -Resource 'Microsoft Graph' -Consent

# Check current scope configuration
Get-EAGAppRegistration -DisplayName MyDemoApp | Get-EAGScope

# Assigns the Graph scope "Group.Read.All" to the Managed Identity of my previously created Automation Account running my Runbooks
Add-EAGMsiScope -DisplayName MyAutomationAccount -Scope Group.Read.All -Resource 'Microsoft Graph'
```
