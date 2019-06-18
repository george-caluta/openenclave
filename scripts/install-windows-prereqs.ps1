# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

Param(
    [string]$GitURL = 'https://github.com/git-for-windows/git/releases/download/v2.20.1.windows.1/Git-2.20.1-64-bit.exe',
    [string]$7zURL = 'https://www.7-zip.org/a/7z1806-x64.msi',
    [string]$VSBuildToolsURL = 'https://aka.ms/vs/15/release/vs_buildtools.exe',
    [string]$OCamlURL = 'http://www.ocamlpro.com/pub/ocpwin/ocpwin-builds/ocpwin64/20160113/ocpwin64-20160113-4.02.1+ocp1-msvc64.zip',
    [string]$Clang7URL = 'http://releases.llvm.org/7.0.1/LLVM-7.0.1-win64.exe',
    [string]$IntelPSWURL = 'http://registrationcenter-download.intel.com/akdlm/irc_nas/15369/Intel%20SGX%20PSW%20for%20Windows%20v2.3.100.49777.exe',
    [string]$ShellCheckURL = 'https://storage.googleapis.com/shellcheck/shellcheck-stable.exe',
    [string]$NugetURL = 'https://dist.nuget.org/win-x86-commandline/latest/nuget.exe',
    [string]$DevconURL = 'https://oejenkins.blob.core.windows.net/oejenkins/devcon.exe',
    [string]$IntelDCAPURL = 'http://registrationcenter-download.intel.com/akdlm/irc_nas/15384/Intel%20SGX%20DCAP%20for%20Windows%20v1.1.100.49925.exe',
    [string]$AzureDCAPNupkgURL = 'https://oejenkins.blob.core.windows.net/oejenkins/Microsoft.Azure.DCAP.Client.1.0.0.nupkg'
)

$ErrorActionPreference = "Stop"

$AZUREDATA_DIRECTORY = Join-Path ${env:SystemDrive} "AzureData"
$AZUREDATA_BIN_DIRECTORY = Join-Path $AZUREDATA_DIRECTORY "bin"
$PACKAGES_DIRECTORY = Join-Path $env:TEMP "packages"
$OE_NUGET_DIR = Join-Path ${env:SystemDrive} 'openenclave\prereqs\nuget'

$PACKAGES = @{
    "git" = @{
        "url" = $GitURL
        "local_file" = Join-Path $PACKAGES_DIRECTORY "Git-2.20.1-64-bit.exe"
    }
    "7z" = @{
        "url" = $7zURL
        "local_file" = Join-Path $PACKAGES_DIRECTORY "7z1806-x64.msi"
    }
    "vs_buildtools" = @{
        "url" = $VSBuildToolsURL
        "local_file" = Join-Path $PACKAGES_DIRECTORY "vs_buildtools.exe"
    }
    "ocaml" = @{
        "url" = $OCamlURL
        "local_file" = Join-Path $PACKAGES_DIRECTORY "ocpwin64.zip"
    }
    "clang7" = @{
        "url" = $Clang7URL
        "local_file" = Join-Path $PACKAGES_DIRECTORY "LLVM-7.0.1-win64.exe"
    }
    "psw" = @{
        "url" = $IntelPSWURL
        "local_file" = Join-Path $PACKAGES_DIRECTORY "Intel_SGX_PSW_for_Windows_v2.3.100.49777.exe"
    }
    "shellcheck" = @{
        "url" = $ShellCheckURL
        "local_file" = Join-Path ${PACKAGES_DIRECTORY} "shellcheck.exe"
    }
    "nuget" = @{
        "url" = $NugetURL
        "local_file" = Join-Path ${PACKAGES_DIRECTORY} "nuget.exe"
    }
    "devcon" = @{
        "url" = $DevconURL
        "local_file" = Join-Path ${PACKAGES_DIRECTORY} "devcon.exe"
    }
    "dcap" = @{
        "url" = $IntelDCAPURL
        "local_file" = Join-Path ${PACKAGES_DIRECTORY} "Intel_SGX_DCAP.exe"
    }
    "azure_dcap_client_nupkg" = @{
        "url" = $AzureDCAPNupkgURL
        "local_file" = Join-Path ${PACKAGES_DIRECTORY} "Microsoft.Azure.DCAP.Client.1.0.0.nupkg"
    }
}

filter Timestamp { "[$(Get-Date -Format o)] $_" }

function Write-Log {
    Param(
        [string]$Message
    )
    $msg = $Message | Timestamp
    Write-Output $msg
}

function New-Directory {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Path,
        [Parameter(Mandatory=$false)]
        [switch]$RemoveExisting
    )
    if(Test-Path $Path) {
        if($RemoveExisting) {
            # Remove if it already exist
            Remove-Item -Recurse -Force $Path
        } else {
            return
        }
    }
    return (New-Item -ItemType Directory -Path $Path)
}

function Start-LocalPackagesDownload {
    Write-Output "Downloading all the packages to local directory: $PACKAGES_DIRECTORY"
    New-Directory ${PACKAGES_DIRECTORY}
    foreach($pkg in $PACKAGES.Keys) {
        Write-Output "Downloading: $($PACKAGES[$pkg]["url"])"
        Start-FileDownload -URL $PACKAGES[$pkg]["url"] `
                           -Destination $PACKAGES[$pkg]["local_file"]
    }
    Write-Output "Finished downloading all the packages"
}

function Start-ExecuteWithRetry {
    Param(
        [Parameter(Mandatory=$true)]
        [ScriptBlock]$ScriptBlock,
        [int]$MaxRetryCount=10,
        [int]$RetryInterval=3,
        [string]$RetryMessage,
        [array]$ArgumentList=@()
    )
    $currentErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $retryCount = 0
    while ($true) {
        Write-Log "Start-ExecuteWithRetry attempt $retryCount"
        try {
            $res = Invoke-Command -ScriptBlock $ScriptBlock `
                                  -ArgumentList $ArgumentList
            $ErrorActionPreference = $currentErrorActionPreference
            Write-Log "Start-ExecuteWithRetry terminated"
            return $res
        } catch [System.Exception] {
            $retryCount++
            if ($retryCount -gt $MaxRetryCount) {
                $ErrorActionPreference = $currentErrorActionPreference
                Write-Log "Start-ExecuteWithRetry exception thrown"
                throw
            } else {
                if($RetryMessage) {
                    Write-Log "Start-ExecuteWithRetry RetryMessage: $RetryMessage"
                } elseif($_) {
                    Write-Log "Start-ExecuteWithRetry Retry: $_.ToString()"
                }
                Start-Sleep $RetryInterval
            }
        }
    }
}

function Start-FileDownload {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$URL,
        [Parameter(Mandatory=$true)]
        [string]$Destination,
        [Parameter(Mandatory=$false)]
        [int]$RetryCount=10
    )
    Start-ExecuteWithRetry -ScriptBlock {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $wc = New-Object System.Net.WebClient
        $wc.DownloadFile($URL,$Destination)
    } -MaxRetryCount $RetryCount -RetryInterval 3 -RetryMessage "Failed to download ${URL}. Retrying"
}

function Add-ToSystemPath {
    Param(
        [Parameter(Mandatory=$false)]
        [string[]]$Path
    )
    if(!$Path) {
        return
    }
    $systemPath = [System.Environment]::GetEnvironmentVariable('Path', 'Machine').Split(';')
    $currentPath = $env:PATH.Split(';')
    foreach($p in $Path) {
        if($p -notin $systemPath) {
            $systemPath += $p
        }
        if($p -notin $currentPath) {
            $currentPath += $p
        }
    }
    $env:PATH = $currentPath -join ';'
    setx.exe /M PATH ($systemPath -join ';')
    if($LASTEXITCODE) {
        Throw "Failed to set the new system path"
    }
}

function Install-Tool {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$InstallerPath,
        [Parameter(Mandatory=$false)]
        [string]$InstallDirectory,
        [Parameter(Mandatory=$false)]
        [string[]]$ArgumentList,
        [Parameter(Mandatory=$false)]
        [string[]]$EnvironmentPath
    )
    if($InstallDirectory -and (Test-Path $InstallDirectory)) {
        Write-Output "$InstallerPath is already installed."
        Add-ToSystemPath -Path $EnvironmentPath
        return
    }
    $parameters = @{
        'FilePath' = $InstallerPath
        'Wait' = $true
        'PassThru' = $true
    }
    if($ArgumentList) {
        $parameters['ArgumentList'] = $ArgumentList
    }
    if($InstallerPath.EndsWith('.msi')) {
        $parameters['FilePath'] = 'msiexec.exe'
        $parameters['ArgumentList'] = @("/i", $InstallerPath) + $ArgumentList
    }
    Write-Output "Installing $InstallerPath"
    $p = Start-Process @parameters
    if($p.ExitCode -ne 0) {
        Throw "Failed to install: $InstallerPath"
    }
    Add-ToSystemPath -Path $EnvironmentPath
    Write-Output "Successfully installed: $InstallerPath"
}

function Install-ZipTool {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$ZipPath,
        [Parameter(Mandatory=$true)]
        [string]$InstallDirectory,
        [Parameter(Mandatory=$false)]
        [string[]]$EnvironmentPath
    )
    if(Test-Path $InstallDirectory) {
        Write-Output "$ZipPath is already installed."
        Add-ToSystemPath -Path $EnvironmentPath
        return
    }
    New-Item -ItemType "Directory" -Path $InstallDirectory
    7z.exe x $ZipPath -o"$InstallDirectory" -y
    if($LASTEXITCODE) {
        Throw "ERROR: Failed to extract $ZipPath to $InstallDirectory"
    }
    Add-ToSystemPath $EnvironmentPath
}

function Install-Git {
    $installDir = Join-Path $env:ProgramFiles "Git"
    Install-Tool -InstallerPath $PACKAGES["git"]["local_file"] `
                 -InstallDirectory $installDir `
                 -ArgumentList @("/SILENT") `
                 -EnvironmentPath @("$installDir\cmd", "$installDir\bin", "$installDir\mingw64\bin")

}

function Install-7Zip {
    $installDir = Join-Path $env:ProgramFiles "7-Zip"
    Install-Tool -InstallerPath $PACKAGES["7z"]["local_file"] `
                 -InstallDirectory $installDir `
                 -ArgumentList @("/quiet", "/passive") `
                 -EnvironmentPath @($installDir)
}

function Install-PSW {
    $installDir = Join-Path $PACKAGES_DIRECTORY "intel_psw_install"
    Install-ZipTool -ZipPath $PACKAGES["psw"]["local_file"] `
                    -InstallDirectory $installDir

    $pswInstaller = Join-Path $installDir "Intel SGX PSW for Windows *\PSW_EXE_RS2_and_before\Intel(R)_SGX_Windows_x64_PSW_*.exe"
    $p = Start-Process -Wait -NoNewWindow -PassThru -FilePath $pswInstaller `
                       -ArgumentList @("--extract-folder", "$installDir", "--x")
    if($p.ExitCode -ne 0) {
        Throw "Failed to extract the Intel SGX PSW bundle: $pswInstaller"
    }
    $p = Start-Process -Wait -NoNewWindow -PassThru -FilePath "$installDir\install.exe" `
                       -ArgumentList @('--s', '--a', 'install', "--output=$installDir\psw-installer.log", '--eula=accept', '--no-progress')
    if($p.ExitCode -ne 0) {
        #Throw "Failed to install the Intel SGX PSW software"
    }
}

function Install-VisualStudio {
    $installerArguments = @(
        "-q", "--wait", "--norestart",
        "--add Microsoft.VisualStudio.Workload.VCTools",
        "--add Microsoft.VisualStudio.Component.VC.CMake.Project"
        "--add Microsoft.VisualStudio.Component.Windows10SDK.17134"
        "--includeRecommended"
    )
    # VisualStudio install sometimes is throwing errors on first try.
    Start-ExecuteWithRetry -ScriptBlock {
       Install-Tool -InstallerPath $PACKAGES["vs_buildtools"]["local_file"] `
                    -ArgumentList $installerArguments
    } -RetryMessage "Failed to install Visual Studio. Retrying"

    [Environment]::SetEnvironmentVariable("VS150COMNTOOLS", "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2017\BuildTools\Common7\Tools", "Machine")
    Add-ToSystemPath -Path '${env:ProgramFiles(x86)}\Microsoft Visual Studio\2017\BuildTools\VC\Auxiliary\Build'
}

function Install-Cmake {
    $installDir = Join-Path $env:ProgramFiles "CMake"

    Install-Tool -InstallerPath $PACKAGES["cmake"]["local_file"] `
                 -InstallDirectory $installDir `
                 -ArgumentList @("/quiet", "/passive") `
                 -EnvironmentPath @("$installDir\bin")
}

function Install-Ocaml {
    $installDir = Join-Path $env:ProgramFiles "OCaml"
    $tmpDir = Join-Path $PACKAGES_DIRECTORY "ocpwin64"
    Install-ZipTool -ZipPath $PACKAGES["ocaml"]["local_file"] `
                    -InstallDirectory $tmpDir `
                    -EnvironmentPath @("$installDir\bin")
    $extractDir = Get-ChildItem $tmpDir | Select-Object -Property Name
    New-Directory -Path $installDir -RemoveExisting
    Copy-Item  "$tmpDir\$($extractDir.Name)\*" -Destination $installDir -Recurse -Force
    $proc = Start-Process -FilePath "$installDir\bin\ocpwin.exe" -ArgumentList "-in" -WorkingDirectory "$installDir\bin" -PassThru -Wait
    if ($proc.ExitCode -ne 0) {
        throw "Failed to install ocaml"
    }
}
function Install-LLVM {
    Install-Tool -InstallerPath $PACKAGES["clang7"]["local_file"] `
                 -ArgumentList "/S"
    Add-ToSystemPath -Path 'C:\Program Files\LLVM\bin'
}

function Install-Shellcheck {
    $shellcheckDest = Join-Path $env:ProgramFiles "shellcheck"
    if(Test-Path -Path $shellcheckDest) {
        Remove-Item -Path $shellcheckDest -Force -Recurse
    }
    New-Item -ItemType Directory -Path $shellcheckDest
    Move-Item "$PACKAGES_DIRECTORY\shellcheck.exe" $shellcheckDest -Force
    Add-ToSystemPath -Path 'C:\Program Files\shellcheck'
}

function Install-DCAPDrivers {
    Install-Tool -InstallerPath $PACKAGES["dcap"]["local_file"] `
                 -ArgumentList @('/auto', "$PACKAGES_DIRECTORY\Intel_SGX_DCAP")

    $drivers = @{
        'sgx_base_dev' = @{
            'zip_path' = "$PACKAGES_DIRECTORY\Intel_SGX_DCAP\Intel SGX DCAP for Windows *\LC_driver_WinServer2016\Signed_*.zip"
            'location' = 'root\SgxLCDevice'
        }
        'sgx_dcap_dev' = @{
            'zip_path' = "$PACKAGES_DIRECTORY\Intel_SGX_DCAP\Intel SGX DCAP for Windows *\DCAP_INF\WinServer2016\Signed_*.zip"
            'location' = 'root\SgxLCDevice_DCAP'
        }
    }
    foreach($driver in $drivers.Keys) {
        $zip = Get-Item $drivers[$driver]['zip_path']
        if(!$zip) {
            Throw "Cannot find the zile file with $driver"
        }
        if($zip.Count -gt 1) {
            $zip
            Throw "Multiple driver zip files found"
        }
        New-Item -ItemType Directory -Force -Path "$PACKAGES_DIRECTORY\Intel_SGX_DCAP\$driver"
        Expand-Archive -Path $zip -DestinationPath "$PACKAGES_DIRECTORY\Intel_SGX_DCAP\$driver" -Force
        $inf = Get-Item "$PACKAGES_DIRECTORY\Intel_SGX_DCAP\$driver\drivers\*\$driver.inf"
        if(!$inf) {
            Throw "Cannot find $driver.inf file"
        }
        if($inf.Count -gt 1) {
            $inf
            Throw "Multiple $driver.inf files found"
        }
        & "$PACKAGES_DIRECTORY\devcon.exe" install "$($inf.FullName)" $drivers[$driver]['location']
        if($LASTEXITCODE) {
            Throw "Failed to install $driver driver"
        }
    }
    $TEMP_NUGET_DIR = "$PACKAGES_DIRECTORY\Azure_DCAP_Client_nupkg"
    New-Directory -Path $OE_NUGET_DIR
    New-Directory -Path $TEMP_NUGET_DIR
    Copy-Item "$PACKAGES_DIRECTORY\Intel_SGX_DCAP\Intel SGX DCAP for Windows *\nupkg\*\*.nupkg" -Destination $TEMP_NUGET_DIR -Force
    Copy-Item $PACKAGES['azure_dcap_client_nupkg']['local_file'] -Destination $TEMP_NUGET_DIR -Force
    & "$PACKAGES_DIRECTORY\nuget.exe" install 'EnclaveCommonAPI' -Source "$TEMP_NUGET_DIR" -OutputDirectory "$OE_NUGET_DIR" -ExcludeVersion
    & "$PACKAGES_DIRECTORY\nuget.exe" install 'DCAP_Components' -Source "$TEMP_NUGET_DIR" -OutputDirectory "$OE_NUGET_DIR" -ExcludeVersion
    & "$PACKAGES_DIRECTORY\nuget.exe" install 'Microsoft.Azure.DCAP.Client' -Source "$TEMP_NUGET_DIR;nuget.org" -OutputDirectory "$OE_NUGET_DIR" -ExcludeVersion

    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\sgx_lc_msr\Parameters" -Name "SGX_Launch_Config_Optin" -Value "1" -PropertyType DWORD -Force
}

try {
    New-Directory -Path ${AZUREDATA_DIRECTORY}
    New-Directory -Path ${AZUREDATA_BIN_DIRECTORY}
    Restart-Computer -Force
    Start-LocalPackagesDownload

    Write-Output "Installing Open Enclave"
    Install-7Zip

    Install-VisualStudio
    Install-LLVM
    Install-Git
    Install-Ocaml
    Install-Shellcheck
    Install-PSW

    Start-ExecuteWithRetry -ScriptBlock {
        #Start-Service "AESMService" -ErrorAction Stop
    } -RetryMessage "Failed to start AESMService. Retrying"

    Copy-Item -Path $PACKAGES["nuget"]["local_file"] -Destination "${AZUREDATA_BIN_DIRECTORY}\nuget.exe"

    Install-DCAPDrivers

    Write-Output 'Please reboot your computer for the configuration to complete.'
}catch {
    Write-Output $_.ToString()
    Write-Output $_.ScriptStackTrace
    exit 1
}
exit 0
