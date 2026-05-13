# Changelog

## 1.1.11 (2026-05-12)

+ Upd: Get-EAGEnterpriseApplication - can now filter for multiple ApplicationTypes in one request.
+ Fix: Add-EAGMsiScope - ignores `-ServiceMap` parameter for actual scope assignment

## 1.1.9 (2025-11-20)

+ New: Get-EAGAppAuthentication - List App Registration authentication settings / options.
+ New: Remove-EAGAppAuthentication - Removes authentication methods from an App Registration.
+ New: Add-EAGAppClientCertificate - Adds a client certificate to an App Registration.
+ New: Add-EAGAppClientSecret - Adds a client secret to an App Registration.
+ New: Add-EAGAppFederatedCredential - Adds a Federated Credential to an App Registration.
+ Upd: Get-EAGEnterpriseApplication - Switched to GraphBeta service name
+ Upd: Get-EAGEnterpriseApplication - Added `ApplicationType` parameter to offer the same filter-presets as used in the portal.
+ Upd: Get-EAGServicePrincipal - Switched to GraphBeta service name

## 1.0.1 (2025-03-24)

+ New: Get-EAGEnterpriseApplication - lists Enterprise Applications

## 1.0.0 (2025-03-23)

+ Initial Release
