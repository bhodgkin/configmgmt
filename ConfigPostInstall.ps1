#################################################################################################################################
#  Name        : Configure-WinRM.ps1                                                                                            #
#                                                                                                                               #
#  Description : Configures the WinRM on a local machine                                                                        #
#                                                                                                                               #
#  Arguments   : HostName, specifies the FQDN of machine or domain                                                           #
#################################################################################################################################

param
(
    [Parameter(Mandatory = $true)]
    [string] $HostName
)

#################################################################################################################################
#                                             Helper Functions                                                                  #
#################################################################################################################################

function Delete-WinRMListener
{
    try
    {
        $config = Winrm enumerate winrm/config/listener
        foreach($conf in $config)
        {
            if($conf.Contains("HTTPS"))
            {
                Write-Verbose "HTTPS is already configured. Deleting the exisiting configuration."
    
                winrm delete winrm/config/Listener?Address=*+Transport=HTTPS
                break
            }
        }
    }
    catch
    {
        Write-Verbose -Verbose "Exception while deleting the listener: " + $_.Exception.Message
    }
}

function Create-Certificate
{
    param(
        [string]$hostname
    )

    # makecert ocassionally produces negative serial numbers
	# which golang tls/crypto <1.6.1 cannot handle
	# https://github.com/golang/go/issues/8265
    $serial = Get-Random
    .\makecert -r -pe -n CN=$hostname -b 01/01/2012 -e 01/01/2022 -eku 1.3.6.1.5.5.7.3.1 -ss my -sr localmachine -sky exchange -sp "Microsoft RSA SChannel Cryptographic Provider" -sy 12 -# $serial 2>&1 | Out-Null

    $thumbprint=(Get-ChildItem cert:\Localmachine\my | Where-Object { $_.Subject -eq "CN=" + $hostname } | Select-Object -Last 1).Thumbprint

    if(-not $thumbprint)
    {
        throw "Failed to create the test certificate."
    }

    return $thumbprint
}

function Configure-WinRMHttpsListener
{
    param([string] $HostName,
          [string] $port)

    # Delete the WinRM Https listener if it is already configured
    Delete-WinRMListener

    # Create a test certificate
    $cert = (Get-ChildItem cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=" + $hostname } | Select-Object -Last 1)
    $thumbprint = $cert.Thumbprint
    if(-not $thumbprint)
    {
	    $thumbprint = Create-Certificate -hostname $HostName
    }
    elseif (-not $cert.PrivateKey)
    {
        # The private key is missing - could have been sysprepped
        # Delete the certificate
        Remove-Item Cert:\LocalMachine\My\$thumbprint -Force
        $thumbprint = Create-Certificate -hostname $HostName
    }

    $WinrmCreate= "winrm create --% winrm/config/Listener?Address=*+Transport=HTTPS @{Hostname=`"$hostName`";CertificateThumbprint=`"$thumbPrint`"}"
    invoke-expression $WinrmCreate
    winrm set winrm/config/service/auth '@{Basic="true"}'
}

function Add-FirewallException
{
    param([string] $port)

    # Delete an exisitng rule
    netsh advfirewall firewall delete rule name="Windows Remote Management (HTTPS-In)" dir=in protocol=TCP localport=$port

    # Add a new firewall rule
    netsh advfirewall firewall add rule name="Windows Remote Management (HTTPS-In)" dir=in action=allow protocol=TCP localport=$port
}
function Fix-NewDisk {
    param([string] $diskName)

    #Command to find disks then initialize then format to GPT and name
    Get-Disk | Where partitionstyle -eq 'raw' | Initialize-Disk -PartitionStyle GPT -PassThru | New-Partition -AssignDriveLetter -UseMaximumSize | Format-Volume -FileSystem NTFS -NewFileSystemLabel "$diskName" -Confirm:$false
}


#################################################################################################################################
#                                              Configure WinRM                                                                  #
#################################################################################################################################

$winrmHttpsPort=5986

# The default MaxEnvelopeSizekb on Windows Server is 500 Kb which is very less. It needs to be at 8192 Kb. The small envelop size if not changed
# results in WS-Management service responding with error that the request size exceeded the configured MaxEnvelopeSize quota.
winrm set winrm/config '@{MaxEnvelopeSizekb = "8192"}'

# Configure https listener
Configure-WinRMHttpsListener $HostName $port

# Add firewall exception
Add-FirewallException -port $winrmHttpsPort


#
# Initalize and Format Disk
#
$name = "Data"
Write-Output "Initializing and formatting DATA disk..."
Fix-NewDisk $name

#
#Set to EST & Set Local User to never Expire                                     
#

Set-TimeZone "Eastern Standard Time"
Install-WindowsFeature RSAT-AD-PowerShell
Import-Module ActiveDirectory
Start-Sleep -Seconds 5
Set-LocalUser -Name luxadmin -PasswordNeverExpires $True

#
#Install and Configure IIS
#
Write-Host "-- Installing IIS --"
DISM.EXE /Enable-Feature /Online /NoRestart /English /FeatureName:IIS-WebServerRole /FeatureName:IIS-WebServer /FeatureName:IIS-CommonHttpFeatures /FeatureName:IIS-StaticContent /FeatureName:IIS-DefaultDocument /FeatureName:IIS-DirectoryBrowsing /featureName:IIS-HttpErrors /featureName:IIS-HttpRedirect /featureName:IIS-ApplicationDevelopment /featureName:IIS-ASPNET /featureName:IIS-NetFxExtensibility /featureName:IIS-ASPNET45 /featureName:IIS-NetFxExtensibility45 /featureName:IIS-ASP /featureName:IIS-CGI /featureName:IIS-ISAPIExtensions /featureName:IIS-ISAPIFilter /featureName:IIS-ServerSideIncludes /featureName:IIS-HealthAndDiagnostics /featureName:IIS-HttpLogging /featureName:IIS-LoggingLibraries /featureName:IIS-RequestMonitor /featureName:IIS-HttpTracing /featureName:IIS-CustomLogging /featureName:IIS-ODBCLogging /featureName:IIS-Security /featureName:IIS-BasicAuthentication /featureName:IIS-WindowsAuthentication /featureName:IIS-DigestAuthentication /featureName:IIS-ClientCertificateMappingAuthentication /featureName:IIS-IISCertificateMappingAuthentication /featureName:IIS-URLAuthorization /featureName:IIS-RequestFiltering /featureName:IIS-IPSecurity /featureName:IIS-Performance /featureName:IIS-HttpCompressionStatic /featureName:IIS-HttpCompressionDynamic /featureName:IIS-WebDAV /featureName:IIS-WebServerManagementTools /featureName:IIS-ManagementScriptingTools /featureName:IIS-ManagementService /featureName:IIS-IIS6ManagementCompatibility /featureName:IIS-Metabase /featureName:IIS-WMICompatibility /featureName:IIS-LegacyScripts /featureName:IIS-FTPServer /featureName:IIS-FTPSvc /featureName:IIS-FTPExtensibility /featureName:NetFx4Extended-ASPNET45 /featureName:IIS-ApplicationInit /featureName:IIS-WebSockets /featureName:IIS-CertProvider /featureName:IIS-ManagementConsole /featureName:IIS-LegacySnapIn

################
##
## Zabbix Installer
##
################


$config_file="C:\Program Files\Zabbix Agent\conf\zabbix_agentd.win.conf"
$ErrorActionPreference = "SilentlyContinue" # Zabbix always errors when installed even when its successfully installed

# Checks for C:\Program Files\Zabbix Agent\, and creates the folder if it doesn't exist
$path = 'C:\Program Files\Zabbix Agent'
If(Test-Path -Path $path){
    Write-Host 'C:\Program Files\Zabbix Agent' already exists -ForegroundColor DarkYellow -BackgroundColor Black
} else {
    New-Item -ItemType Directory -Path 'C:\Program Files\Zabbix Agent' -Force
}

# Specifies a TLS connection to use for certain OS to use.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Downloads Zabbix
$url = "https://s3-eu-west-1.amazonaws.com/hu-deployment-repo/zabbix/agent/zabbix-3.2.7-with-mbed-TLS-1.3.21-x86-64.zip"
$output = "$($PSScriptRoot)\zabbix-3.2.7-with-mbed-TLS-1.3.21-x86-64.zip"
(New-Object System.Net.WebClient).DownloadFile($url, $output)

# Unzip Zabbix
Add-Type -assembly "system.io.compression.filesystem"
$destination 
[io.compression.zipfile]::ExtractToDirectory($output, $path)

# Pauses until zabbix has been unzipped
$test = Test-Path -Path 'C:\Program Files\Zabbix Agent\bin'
While($test -eq $false){
    Write-Host "Waiting on download and extraction..." -ForegroundColor DarkYellow -BackgroundColor Black
    $test = Test-Path -Path "C:\Program Files\Zabbix Agent\bin"
}

# Install the agent
& "C:\Program Files\Zabbix Agent\bin\win64\zabbix_agentd.exe" -c $config_file -i

# Set log file path
(Get-Content $config_file).Replace("LogFile=c:\zabbix_agentd.log","LogFile=C:\Program Files\Zabbix Agent\zabbix_agentd.log") | Set-Content $config_file

# Enable remote commands 
(Get-Content $config_file).Replace("# EnableRemoteCommands=0","EnableRemoteCommands=1") | Set-Content $config_file

# Set local proxy as the server 
(Get-Content $config_file).Replace("Server=127.0.0.1","Server=zabbix.hentsu.net") | Set-Content $config_file
(Get-Content $config_file).Replace("ServerActive=127.0.0.1","ServerActive=zabbix.hentsu.net") | Set-Content $config_file

# Remove hostname entry to allow auto registration
(Get-Content $config_file).Replace("Hostname=Windows host","# Hostname=Windows host") | Set-Content $config_file

# Set host metadata for auto registration
(Get-Content $config_file).Replace("# HostMetadata=","HostMetadata=WindowsAgentAutoCheckIn") | Set-Content $config_file

$svcStat = Get-Service -Name 'Zabbix Agent'
Write-Host "Zabbix Agent service is currently $($svcStat.Status). Performing post-install reboot..." -ForegroundColor DarkYellow -BackgroundColor Black
Start-Service -Name "Zabbix Agent"
Write-Host "Waiting 5 seconds before checking service status..." -ForegroundColor DarkYellow -BackgroundColor Black
Start-Sleep -Seconds 5
Get-Service -Name "Zabbix Agent"

# Add firewall rule to allow zabbix port 10050
New-NetFirewallRule -DisplayName "Zabbix Port" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 10050

Sleep -s 60

# Create PSK file
$pskpath ="C:\Program Files\Zabbix Agent\conf\tls_key.psk"
New-Item $pskpath -ItemType File
add-Content $pskpath "acebd01d4859db19b6e9ae3feec6eb11"

# Set TLSPSKFile
(Get-Content $config_file).Replace("# TLSPSKFile=","TLSPSKFile=C:\Program Files\Zabbix Agent\conf\tls_key.psk") | Set-Content $config_file

# Set TLS Identity
(Get-Content $config_file).Replace("# TLSPSKIdentity=","TLSPSKIdentity=RI\hentsupsk") | Set-Content $config_file

# Set TLS Connect
(Get-Content $config_file).Replace("# TLSConnect=unencrypted","TLSConnect=psk") | Set-Content $config_file

# Set TLS Accept
(Get-Content $config_file).Replace("# TLSAccept=unencrypted","TLSAccept=psk") | Set-Content $config_file

$svcStat = Get-Service -Name 'Zabbix Agent'
Write-Host "Zabbix Agent service is currently $($svcStat.Status). Performing post-install service restart..." -ForegroundColor DarkYellow -BackgroundColor Black
Restart-Service -Name "Zabbix Agent"
Write-Host "Waiting 5 seconds before checking service status..." -ForegroundColor DarkYellow -BackgroundColor Black
Start-Sleep -Seconds 5
Get-Service -Name "Zabbix Agent"


