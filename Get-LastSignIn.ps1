function New-LoggingDirectory {
    <#
        .SYNOPSIS
            Create directories

        .DESCRIPTION
            Create the root and all subfolder needed for logging

        .PARAMETER LoggingPath
            Logging Path

        .PARAMETER SubFolder
            Switch to indicated we are creating a subfolder

        .PARAMETER SubFolderName
            Subfolder Name

        .EXAMPLE
            PS C:\New-LoggingDirectory -SubFolder SubFolderName

        .NOTES
            Internal function
    #>

    [OutputType('System.IO.Folder')]
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]
        $LoggingPath,

        [switch]
        $SubFolder,

        [string]
        $SubFolderName
    )

    begin {
        if (-NOT($SubFolder)) {
            Write-Verbose "Creating directory: $($LoggingPath)"
        }
        else {
            Write-Verbose "Creating directory: $LoggingPath\$SubFolderName)"
        }
    }

    process {
        try {
            # Leaving this here in case the root directory gets deleted between executions so we will re-create it again
            if (-NOT(Test-Path -Path $LoggingPath)) {
                if (New-Item -Path $LoggingPath -ItemType Directory -ErrorAction Stop) {
                    Write-Verbose "$LoggingPath directory created!"
                }
                else {
                    Write-Verbose "$($LoggingPath) already exists!"
                }
            }
            if ($SubFolder) {
                if (-NOT(Test-Path -Path $LoggingPath\$SubFolderName)) {
                    if (New-Item -Path $LoggingPath\$SubFolderName -ItemType Directory -ErrorAction Stop) {
                        Write-Verbose "$LoggingPath\$SubFolderName directory created!"
                    }
                    else {
                        Write-Verbose "$($SubFolderName) already exists!"
                    }
                }
            }
        }
        catch {
            Write-Output "Error: $_"
            return
        }
    }

}

function Get-LastSignIn {
    <#
        .SYNOPSIS
            Export Azure Sign-in logs

        .DESCRIPTION
            Connect using Graph API and export Azure AD Sign-in logs from a global, GCC or DoD tenant

        .PARAMETER Endpoint
            Endpoint to connect to

        .PARAMETER LoggingPath
            Logging path

        .PARAMETER ResourceType
            Graph namespace to retrieve

        .PARAMETER RemoveBlanks
            Exclude results that do not have a last login date

        .PARAMETER SaveResultsToCSV
            Save results to disk in CSV format

        .PARAMETER SaveResultsToJSON
            Save results to disk in JSON format

        .PARAMETER ShowModuleInfoInVerbose
            Used to troubleshoot module install and import

        .PARAMETER ShowLast90Days
            Show results of the last 90 days of logins

        .PARAMETER ShowLastSignInDateTime
            Show results from last sign in date

        .PARAMETER ShowLastNonInteractiveSignInDateTime
            Show results from last non-interactive sign in date

        .EXAMPLE
            PS C:\Get-LastSignIn

            Retrieves Azure AD Sign-in logs

        .EXAMPLE
            PS C:\Get-LastSignIn

            Retrieves Azure AD Sign-in logs

        .EXAMPLE
            PS C:\Get-LastSignIn -Endpoint Commercial

            Retrieves Azure AD Sign-in logs from a commercial endpoint

        .EXAMPLE
            PS C:\Get-LastSignIn -ResourceType -SaveResultsToCSV

            Retrieves Azure AD Sign-in logs and saves them in csv format

        .EXAMPLE
            PS C:\Get-LastSignIn -ResourceType -SaveResultsToJSON

            Retrieves Azure AD Sign-in logs and saves them in json format

        .NOTES
            https://learn.microsoft.com/en-us/graph/filter-query-parameter
            https://learn.microsoft.com/en-us/powershell/microsoftgraph/get-started?view=graph-powershell-1.0
            https://learn.microsoft.com/en-us/graph/api/resources/intune-shared-devicemanagement?view=graph-rest-beta

            In addition to the delegated permissions, the signed-in user needs to belong to one of the following directory roles that allow them to read sign-in reports.
            To learn more about directory roles, see Azure AD built-in roles:

            Global Administrator
            Global Reader
            Reports Reader
            Security Administrator
            Security Operator
            Security Reader
   #>

    [OutputType('PSCustomObject')]
    [CmdletBinding()]
    [Alias('GetSil')]
    param(
        [ValidateSet('Global', 'GCC', 'DOD')]
        [parameter(Position = 0)]
        [string]
        $Endpoint = 'Global',

        [parameter(Position = 1)]
        $LoggingPath = "$env:Temp\ExportedAzureSignInLogs",

        [ValidateSet('?select=displayName,signInActivity', '?filter=userType eq ''Guest''&select=displayName,id')]
        [parameter(Position = 2)]
        [string]
        $ResourceType = '?select=displayName,signInActivity',

        [switch]
        $RemoveBlanks,

        [switch]
        $SaveResultsToCSV,

        [switch]
        $SaveResultsToJSON,

        [switch]
        $ShowModuleInfoInVerbose,

        [switch]
        $ShowLast90Days,

        [switch]
        $ShowLastSignInDateTime,

        [switch]
        $ShowLastNonInteractiveSignInDateTime
    )

    begin {
        Write-Output "Retrieving AD Sign-in logs"
        $parameters = $PSBoundParameters
        [System.Collections.ArrayList]$userList = @()
        $modules = @("Microsoft.Graph.Authentication", "Microsoft.Graph.Reports")
        $successful = $false
    }

    process {
        if ($PSVersionTable.PSEdition -ne 'Core') {
            Write-Output "You need to run this script using PowerShell core due to dependencies."
            return
        }

        # Create root directory
        New-LoggingDirectory -LoggingPath $LoggingPath

        try {
            foreach ($module in $modules) {
                if ($found = Get-Module -Name $module -ListAvailable | Sort-Object Version | Select-Object -First 1) {
                    if (Import-Module -Name $found -ErrorAction Stop -Verbose:$ShowModuleInfoInVerbose -PassThru) {
                        Write-Verbose "$found imported!"
                        $successful = $true
                    }
                    else {
                        Throw "Error importing $($found). Please Run Export-IntunePolicy -Verbose -ShowModuleInfoInVerbose"
                    }
                }
                else {
                    Write-Output "$module not found! Installing module $($module) from the PowerShell Gallery"
                    if (Install-Module -Name $module -Repository PSGallery -Force -Verbose:$ShowModuleInfoInVerbose -PassThru) {
                        Write-Verbose "$module installed successfully! Importing $($module)"
                        if (Import-Module -Name $module -ErrorAction Stop -Verbose:$ShowModuleInfoInVerbose -PassThru) {
                            Write-Verbose "$module imported successfully!"
                            $successful = $true
                        }
                        else {
                            Throw "Error importing $($found). Please Run Export-IntunePolicy -Verbose -ShowModuleInfoInVerbose"
                        }
                    }
                }
            }
        }
        catch {
            Write-Output "Error: $_"
            return
        }

        try {
            if ($successful) {
                Select-MgProfile -Name "beta" -ErrorAction Stop
                Write-Verbose "Using MGProfile (Beta)"
                If ($Endpoint -eq 'Global') { Connect-MgGraph -Scopes "User.Read.All", "AuditLog.Read.All", "Directory.Read.All" -Environment Global -ForceRefresh -ErrorAction Stop }
                if ($Endpoint -eq 'GCC') { Connect-MgGraph -Scopes "User.Read.All", "AuditLog.Read.All", "Directory.Read.All" -Environment USGov -ForceRefresh -ErrorAction Stop }
                if ($Endpoint -eq 'Dod') { Connect-MgGraph -Scopes "User.Read.All", "AuditLog.Read.All", "Directory.Read.All" -Environment USGovDoD -ForceRefresh -ErrorAction Stop }
            }
            else {
                Write-Output "Error: Unable to connect to the Graph endpoint. $_"
                return
            }
        }
        catch {
            Write-Output "Error: $_"
            return
        }

        try {
            switch ($Endpoint) {
                'Global' {
                    $uri = "https://graph.microsoft.com/beta/users$ResourceType"
                    continue
                }
                'GCC' {
                    $uri = "https://graph.microsoft.us/beta/users$ResourceType"
                    continue
                }
                'DoD' {
                    $uri = "https://dod-graph.microsoft.us/beta/users$ResourceType"
                    continue
                }
            }

            Write-Output "Querying Graph uri: $($uri)"
            if ($users = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop) {
                if ($parameters.ContainsKey('ShowLastSignInDateTime')) { $typeName = 'ShowLastSignInDateTime' } else { $typeName = 'GeneralType' }
                if ($parameters.ContainsKey('ShowLastNonInteractiveSignInDateTime')) { $typeName = 'ShowLastNonInteractiveSignInDateTime' } else { $typeName = 'GeneralType' }
                if ($parameters.ContainsKey('ShowLast90Days')) { $typeName = 'ShowLast90Days' } else { $typeName = 'GeneralType' }
                foreach ($user in $users.value) {
                    $userFound = [PSCustomObject]@{
                        PSTypeName                        = "Sign-In $typeName"
                        displayName                       = $user.displayName
                        lastSignInDateTime                = if (-NOT($user.signInActivity.lastSignInDateTime)) { 'None' } else { $user.signInActivity.lastSignInDateTime }
                        lastSignInRequestId               = if (-NOT($user.signInActivity.lastSignInRequestId)) { 'None' } else { $user.signInActivity.lastSignInRequestId }
                        lastNonInteractiveSignInDateTime  = if (-NOT($user.signInActivity.lastNonInteractiveSignInDateTime)) { 'None' } else { $user.signInActivity.lastNonInteractiveSignInDateTime }
                        lastNonInteractiveSignInRequestId = if (-NOT($user.signInActivity.lastNonInteractiveSignInRequestId)) { 'None' } else { $user.signInActivity.lastNonInteractiveSignInRequestId }
                    }
                    if ($parameters.ContainsKey('ShowLast90Days') -and ($userFound.lastSignInDateTime -ne 'None') -and ($userFound.lastSignInDateTime -ne 'Monday, January 1, 0001 12:00:00 AM')) {
                        $last90Days = ([System.DateTime]$user.signInActivity.lastSignInDateTime).AddDays(-90)
                        $userFound | Add-Member -MemberType NoteProperty -Name Minus90Days -Value $last90Days -ErrorAction Stop
                    }
                    $null = $userList.add($userFound)
                }
            }
            else {
                Write-Output "No results returned!"
            }
        }
        catch {
            Write-Output "Error: $_"
        }

        try {
            # If no data was found then bail out
            if ($userList.count -eq 0) {
                Write-Output "Not data found!"
                return
            }

            if ($parameters.ContainsKey('SaveResultsToCSV')) {
                New-LoggingDirectory -LoggingPath $LoggingPath -SubFolder $typeName
                Write-Verbose "Saving $($typeName + ".csv")"
                [PSCustomObject]$userList | Export-Csv -Path (Join-Path -Path $LoggingPath\$typeName -ChildPath $($typeName + ".csv")) -Encoding UTF8 -NoTypeInformation -ErrorAction Stop
            }

            if ($parameters.ContainsKey('SaveResultsToJSON')) {
                New-LoggingDirectory -LoggingPath $LoggingPath -SubFolder $typeName
                [PSCustomObject]$userList | ConvertTo-Json -Depth 10 | Set-Content (Join-Path -Path $LoggingPath\$typeName -ChildPath $($typeName + ".json")) -ErrorAction Stop -Encoding UTF8
                Write-Verbose "Saving $($typeName + ".json")"
            }
        }
        catch {
            Write-Output "Error: $_"
        }

        try {
            # Display to the console results
            if ($parameters.ContainsKey('ShowLastSignInDateTime')) {
                $TypeData = @{
                    TypeName                  = "Sign-In $typeName"
                    DefaultDisplayPropertySet = 'DisplayName', 'lastSignInDateTime'
                }
                Update-TypeData @TypeData
                if ($parameters.ContainsKey('RemoveBlanks')) { [PSCustomObject]$userList | Where-Object lastSignInDateTime -ne 'None' } else { [PSCustomObject]$userList }
                Remove-TypeData -TypeName "Sign-In $typeName"
            }
            elseif ($parameters.ContainsKey('ShowLastNonInteractiveSignInDateTime')) {
                $TypeData = @{
                    TypeName                  = "Sign-In $typeName"
                    DefaultDisplayPropertySet = 'DisplayName', 'lastNonInteractiveSignInDateTime'
                }
                Update-TypeData @TypeData
                if ($parameters.ContainsKey('RemoveBlanks')) { [PSCustomObject]$userList | Where-Object lastNonInteractiveSignInDateTime -ne 'None' } else { [PSCustomObject]$userList }
                Remove-TypeData -TypeName "Sign-In $typeName"
            }
            elseif ($parameters.ContainsKey('ShowLast90Days')) {
                $TypeData = @{
                    TypeName                  = "Sign-In $typeName"
                    DefaultDisplayPropertySet = 'DisplayName', 'lastSignInDateTime', 'minus90days'
                }
                Update-TypeData @TypeData
                if ($parameters.ContainsKey('RemoveBlanks')) { [PSCustomObject]$userList | Where-Object lastSignInDateTime -ne 'None' } else { [PSCustomObject]$userList }
                Remove-TypeData -TypeName "Sign-In $typeName"
            }
            else {
                $TypeData = @{
                    TypeName                  = "Sign-In $typeName"
                    DefaultDisplayPropertySet = 'DisplayName', 'lastSignInDateTime', 'lastSignInRequestId', 'lastNonInteractiveSignInDateTime'
                }
                Update-TypeData @TypeData
                [PSCustomObject]$userList
                Remove-TypeData -TypeName "Sign-In $typeName"
            }
        }
        catch {
            Write-Output "Error: $_"
        }
    }

    end {
        if (($userList.Count -gt 0) -and ($parameters.ContainsKey('SaveResultsToCSV') -or ($parameters.ContainsKey('SaveResultsToJSON')))) {
            Write-Output "`nResults exported to: $($LoggingPath)`nCompleted!"
        }
        else {
            $null = Disconnect-MgGraph
            Write-Output "Completed!"
        }
    }
}