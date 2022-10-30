# Get-LastSignIn

Connect using Graph API and export Azure AD Sign-in logs from a global, GCC or DoD tenant

## Getting Started with Get-LastSignIn
You must be running PowerShell 7 for this script to work due to dependencies.

Running this script you agree to install Microsoft.Graph PowerShell modules and consent to permissions on your system so you can connect to GraphAPI to export Intune policy information

### DESCRIPTION

Connect using Graph API (Beta) and export Azure Sign-in logs.

### Examples

- EXAMPLE 1: PS C:\Get-LastSignIn

    Retrieves Azure AD Sign-in logs

- EXAMPLE 2: PS C:\Get-LastSignIn

    Retrieves Azure AD Sign-in logs

- EXAMPLE 3: PS C:\Get-LastSignIn -Endpoint Commercial

    Retrieves Azure AD Sign-in logs from a commercial endpoint

- EXAMPLE 4: PS C:\Get-LastSignIn -ResourceType -SaveResultsToCSV

    Retrieves Azure AD Sign-in logs and saves them in csv format

- EXAMPLE 5: PS C:\Get-LastSignIn -ResourceType -SaveResultsToJSON

    Retrieves Azure AD Sign-in logs and saves them in json format

### Note on file export

All policies will be exported in csv or json to "$env:Temp\ExportedIntunePolicies". This path can be changed if necessary.
