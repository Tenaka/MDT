
<#
.Synopsis

Automate the installation and configuration of MDT, ADK, DHCP and WDS to allow PXE and deployment of OEM Windows 10.

.DESCRIPTION

Server Spec:
VM or Physical Server
    C:\ 60Gb min
    D:\ 60Gb 
    2048Gb RAM
    2 * Cores

Windows Server 2016 or above (works on 2012)

Media Required copying to the the following locations:
    ADK                              saved to C:\Media\ADK
    ADKPE                            saved to C:\Media\ADKPE
    MDTx64                           saved to C:\Media\MDT
    Windows 10 iso                   saved to c:\Media\Win10
    SXS from Server Install media    saved to C:\Media\sxs 

ADK and ADK PE
https://docs.microsoft.com/en-us/windows-hardware/get-started/adk-install

MDT 
https://www.microsoft.com/en-us/download/details.aspx?id=54259


.VERSION
210716.01 - created 


#>

if (-not([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{Write-Host "An elevated administrator account is required to run this script." -BackgroundColor Red}

else
{
    #Confirm that software is present and saved to the correct paths
    $swADK = "C:\Media\ADK\adksetup.exe"
    $swPE = "C:\Media\ADKPE\adkwinpesetup.exe"
    $swMDT = "C:\Media\MDT\MicrosoftDeploymentToolkit_x64.msi"
    $swSXS = "C:\Media\sxs"
    $swWin10 = "C:\Media\Win10"

    $swPaths = $swADK, $swPE, $swMDT, $swSXS

    foreach ($software in $swPaths)
    {
    $tpSoft = Test-Path $software
    if ($tpSoft -eq $true)
        {
        Write-Host "$software is present" -ForegroundColor Green
        }
    else 
        {
        Write-Host "$software is missing" -ForegroundColor red
        }

    }

    $hostn = Hostname

    $gNetAdp = Get-NetAdapter | where {$_.Status -eq "up"}
        $intAlias = $gNetAdp.InterfaceAlias

    $gNetIPC = Get-NetIPConfiguration -InterfaceAlias $gNetAdp.Name
        $IPAddress = $gNetIPC.IPv4Address.ipaddress
        $DHCPRouter = $gNetIPC.IPv4DefaultGateway.nexthop
        $dnsAddress = $gNetIPC.dnsserver.serveraddresses

    $gNetIPC | Remove-NetIPAddress -Confirm:$false
    $gNetIPC.IPv4DefaultGateway |Remove-NetRoute -Confirm:$false

    $IPAddress = Read-Host "Enter the Static IP for the MDT Server"
    $ScopeID = Read-Host "Enter Scope ID eg 192.168.0.0"
    $scopeName = "MDT Client Deployment Scope"
    $DHCPStart = Read-Host "Enter the start of a DHCP IP range eg 192.168.0.1"
    $DHCPEnd = Read-Host "Enter the end of the DHCP IP range eg 192.168.0.100"
    $DHCPSub = Read-Host "Enter the Subnet eg 255.255.255.0"
    $DefGate = Read-Host "Enter the Default Gateway eg 192.168.0.254"
    $dnsServer = Read-Host "Enter DNS IP(s) eg 192.168.0.22 or 192.168.0.22,192.168.0.23"
    $dnsName = Read-Host "Enter an FQDN eg Contoso.net"

    
    #Set Static IP
    New-NetIPAddress -InterfaceAlias $gNetAdp.Name `
                     -IPAddress $IPAddress `
                     -AddressFamily IPv4 `
                     -PrefixLength $gNetIP.PrefixLength `
                     -DefaultGateway $DefGate 
    #Set DNS Server                 
    Set-DnsClientServerAddress -ServerAddresses $dnsServer -InterfaceAlias $intAlias

    ############################################################################################
    ##########################  INSTALL WINDOWS FEATURES, MDT AND ADK  #########################
    ############################################################################################

    #Install DHCP and WDS Features
    Install-WindowsFeature -Name DHCP,RSAT-DHCP,WDS,WDS-AdminPack

    #Install .Net Framework - required for SQL Databased
    Install-WindowsFeature -Name NET-Framework-Core -Source C:\media\sxs

    #Identify data drive 
    $psDataDrv = psdrive | where {$_.Provider -like "*File*" -and $_.name -ne "C" -and $_.Free -ne "0" -and $_.Free -ne $null}

    #Set Data Drive Letter as variable
    $drv = ($psDataDrv).Name + ":"
    $tpDrv = Test-Path $drv

    #Set installation path for ADK and MDT
    if ($tpDrv -eq $true)
        {
        $installPath = "$drv" +"\Program Files\Windows Kits"
        }
    else 
        {
        $installPath = "C:\Program Files\Windows Kits"
        }

    #Install ADK
    cmd.exe /c C:\Media\ADK\adksetup.exe /Quiet /InstallPath $installPath /Features OptionId.DeploymentTools OptionID.UserStateMigrationTool OptionId.ImagingAndConfigurationDesigner OptionId.ICDConfigurationDesigner
    #Install ADL PE
    cmd.exe /c C:\Media\ADKPE\adkwinpesetup.exe /features + /q 

    #Install MDT
    cmd.exe /c msiexec.exe /i C:\Media\MDT\MicrosoftDeploymentToolkit_x64.msi /l C:\Media\MDT_Setup.log /q

    ############################################################################################
    #################################  DEPLOY DHCP SERVER  #####################################
    ############################################################################################

    #Creates DHCP Scope
    Add-DhcpServerv4Scope -ComputerName $hostn `
                          -Name $scopeName `
                          -StartRange $DHCPStart `
                          -EndRange $DHCPEnd `
                          -SubnetMask $DHCPSub `
                          -Description "MDT Client Deployment Scope" `
                          -State Active 

    $scopeID = Get-DhcpServerv4Scope -ComputerName $hostn | where {$_.name -eq $scopeName} | Select-Object Scopeid

    #Adds Scope options 
    Set-DhcpServerv4OptionValue -ComputerName $hostn -OptionId 001 -Value 0x2 -ScopeId $scopeID.ScopeId -Force
    Set-DhcpServerv4OptionValue -ComputerName $hostn -OptionId 003 -value $DefGate -ScopeId $scopeID.ScopeId
    Set-DhcpServerv4OptionValue -ComputerName $hostn -OptionId 006 -value $dnsServer -ScopeId $scopeID.ScopeId -Force
    Set-DhcpServerv4OptionValue -ComputerName $hostn -OptionId 015 -value $dnsName -ScopeId $scopeID.ScopeId -Force
    Set-DhcpServerv4Optionvalue -ComputerName $hostn -OptionId 066 -Value $IPAddress -ScopeId $scopeID.ScopeId
    Set-DhcpServerv4Optionvalue -ComputerName $hostn -OptionId 067 -Value "boot\x64\bootmgfw.efi" -ScopeId $scopeID.ScopeId

    ############################################################################################
    ######################  CREATE MDT SERVICE ACCOUNT AND SET UP SHARES  ######################
    ############################################################################################

    #Generate Random Password for MDTUser Service Account
    $mdtUser = "MDTUser"
    $pwl = 14
    $sysWeb = Add-Type -AssemblyName system.web
    $randPass = [System.Web.Security.Membership]::GeneratePassword($pwl,3)

    $svcPass = ConvertTo-SecureString $randPass -AsPlainText -Force 

    New-LocalUser    -Name $mdtUser `
                     -Description "MDT Service Account" `
                     -FullName $mdtUser `
                     -Password $svcPass `
                     -AccountNeverExpires `
                     -PasswordNeverExpires

    #Paths and Shares
    $mdtRoot = "$drv"+"\MDTDeploymentShare"
    $mdtLogs = "$mdtRoot\logs"
    $mdtCap = "$mdtRoot\captures"
    $mdtDes = "MDT Deployment Share"

    $mdtShRoot = "MDTDeploymentShare$"
    $mdtShLogs = "Logs$"
    $mdtShCap = "Captures$"

    $mdtShRtDes = "MDT Deployment Share"

    #Add MDT Module and create new MDT Root
    Add-PSSnapin Microsoft.BDD.PSSnapin
    New-Item -Path $mdtRoot -ItemType Directory
    New-PSDrive -Name 'DS001' `
                -PSProvider "MDTProvider" `
                -Root $mdtRoot `
                -Description 'MDT Deployment Share' `
                -Networkpath "\\$hostn\$mdtShRoot" |
                    Add-MDTPersistentDrive New-SmbShare $mdtShare 

    #MDT Root grants Svc Read access 
    New-SmbShare -ReadAccess $mdtuser -Path $mdtRoot -Name $mdtShRoot -Description $mdtShRtDes

    #MDT Root requires Admin modify access to create\update unattend.xml
    Grant-FileShareAccess -Name $mdtShRoot -AccountName Administrators -AccessRight Modify

    #Logging Share grants svc Modify access
    New-SmbShare -ChangeAccess $mdtUser -Path $mdtLogs -Name $mdtShLogs -Description "Logs Share"

    #Capture share grants svc Modify access to upload deployed captures
    New-SmbShare -ChangeAccess $mdtUser -Path $mdtCap -Name $mdtShCap -Description "Capture Share"

    #Inheritence 
    $inherNone = [System.Security.AccessControl.InheritanceFlags]::None
    $propNone = [System.Security.AccessControl.PropagationFlags]::None
    $inherCnIn = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit
    $propInOn = [System.Security.AccessControl.PropagationFlags]::InheritOnly
    $inherObIn = [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $propNoPr = [System.Security.AccessControl.PropagationFlags]::NoPropagateInherit

    #Sets MDTUser permission over MDTRoot
    $aclMdtRoot = Get-Acl $MdtRoot
    $arMdtRoot = New-Object System.Security.AccessControl.FileSystemAccessRule("$mdtUser","READ","$inherCnIn,$inherObIn","None","Allow")
    $aclMdtRoot.SetAccessRule($arMdtRoot)
    Set-Acl $MdtRoot $aclMdtRoot

    #Creates Root\Logs
    New-Item -Path $mdtLogs -ItemType Directory -Force

    #Removes Inherit
    $aclmdtLogs = get-acl $mdtLogs
    $aclmdtLogs.SetAccessRuleProtection($true,$true)
    Set-Acl $mdtLogs $aclmdtLogs

    #MDTUser gets modify permissons 
    $aclMDTLogs = Get-Acl $mdtLogs
    $arMDTLogs = New-Object System.Security.AccessControl.FileSystemAccessRule("$mdtUser","MODIFY","$inherCnIn,$inherObIn","None","Allow")
    $aclMDTLogs.SetAccessRule($arMDTLogs)
    Set-Acl $mdtLogs $aclMDTLogs

    #Removes Inherit
    $aclmdtCap = get-acl $mdtCap
    $aclmdtCap.SetAccessRuleProtection($true,$true)
    Set-Acl $mdtCap $aclmdtCap

    #Sets Modify permission over Captures Folder
    $aclmdtCap = Get-Acl $mdtCap
    $armdtCap = New-Object System.Security.AccessControl.FileSystemAccessRule("$mdtUser","MODIFY","$inherCnIn,$inherObIn","None","Allow")
    $aclmdtCap.SetAccessRule($armdtCap)
    Set-Acl $mdtCap $aclmdtCap

    ############################################################################################
    ################################  CONFIG MDT SETTINGS  #####################################
    ############################################################################################

    #Enable MDT Monitoring
    Enable-MDTMonitorService -DataPort 9801 -EventPort 

    #Import MDT Powershell Module
    Import-Module "$installPath" + "\bin\MicrosoftDeploymentToolkit.psd1"

    #Win10-PE Profiles created
    New-PSDrive -Name "DS001" -PSProvider MDTProvider -Root $mdtRoot
    New-Item -path "DS001:\Selection Profiles" -enable "True" -Name "Win10PE_Drivers" -Comments "Only add Network and Storage drivers to this profile" -Definition "<SelectionProfile />" -ReadOnly "False" -Verbose

    #Update Settings.xml to set x64 boot media settings
    $gcSettings = Get-Content $mdtRoot\Control\Settings.xml 
    $gcSettings.Replace("<Boot.x64.ScratchSpace>32</Boot.x64.ScratchSpace>","<Boot.x64.ScratchSpace>512</Boot.x64.ScratchSpace>") | 
    Out-File $mdtRoot\Control\Settings.xml
    $gcSettings.Replace("<Boot.x64.ScratchSpace>32</Boot.x64.ScratchSpace>","<Boot.x64.GenerateGenericWIM>True</Boot.x64.GenerateGenericWIM>") | 
    Out-File $mdtRoot\Control\Settings.xml
    $gcSettings.Replace("<Boot.x64.SelectionProfile>All Drivers and Packages</Boot.x64.SelectionProfile>","<Boot.x64.SelectionProfile>Win10PE_Drivers</Boot.x64.SelectionProfile>") | 
    Out-File $mdtRoot\Control\Settings.xml
    $gcSettings.Replace("<Boot.x64.GenerateGenericWIM>False</Boot.x64.GenerateGenericWIM>","<Boot.x64.GenerateGenericWIM>True</Boot.x64.GenerateGenericWIM>") | 
    Out-File $mdtRoot\Control\Settings.xml

    ############################################################################################
    ########################  CREATE BOOT MEDIA, IMPORT AND INIT WDS  ##########################
    ############################################################################################

    #Generate boot media
    New-PSDrive -Name "DS001" -PSProvider MDTProvider -Root "$mdtRoot"
    update-MDTDeploymentShare -path "DS001:" -Force -Verbose

    #init WDS
    & wdsutil.exe /Initialize-Server /Server:$hostn /reminst:"$remDir`:\RemoteInstall" /standalone

    #Import WDS Boot image generated by MDT
    Import-WdsBootImage -NewImageName "Lite Touch Windows PE (x64)" -NewFileName "LiteTouchPE_x64.wim" -Path $mdtRoot\boot\LiteTouchPE_x64.wim 


    ############################################################################################
    ############################  IMPORT WINDOWS 10 MEDIA  #####################################
    ############################################################################################

    #Mount Windows ISO 
    Mount-DiskImage -ImagePath (Get-ChildItem C:\Media\Win10 -Filter *.iso).FullName

    $psISO = (psdrive | where {$_.Free -eq "0"}).Name

    #New Folder for Windows 10 Images
    New-PSDrive -Name "DS001" -PSProvider MDTProvider -Root "$mdtRoot"
    New-Item -path "DS001:\Operating Systems" -enable "True" -Name "Windows 10" -Comments "" -ItemType "folder" -Verbose

    #Import Windows 10 into MDT
    Import-MDTOperatingSystem -path "DS001:\Operating Systems\Windows 10" -SourceFile "$psISO`:\sources\install.wim" -DestinationFolder "Windows 10" -Verbose

    #New Folder for Gold Image Task Sequences
    New-Item -path "DS001:\Task Sequences" -enable "True" -Name "Windows 10 Gold Image" -Comments "" -ItemType "folder" -Verbose

    #List avaiable Windows 10 versions in wim file - Select Pro or Enterprise 
    $gcOSImage = (Get-Content "$mdtRoot\Control\OperatingSystems.xml" -Delimiter / | Select-String "<ImageName>")-replace("</","")-replace("ImageIndex><ImageName>","")

    $tsID = "Win10-Gold-001"

    if ($gcOSImage -match "Windows 10 Enterprise" )
        { 
        #New Task Sequence for Windows 10 Enterprise
        Import-MDTTaskSequence -path "DS001:\Task Sequences\Windows 10 Gold Image" -Name "Windows 10 Enterprise Gold Image" -Template "Client.xml" -Comments "" -ID $tsID -Version "1.0" -OperatingSystemPath "DS001:\Operating Systems\Windows 10\Windows 10 Enterprise in Windows 10 install.wim" -FullName "Windows User" -OrgName "Contoso" -HomePage "about:blank" -Verbose
        }
    else
        { 
        #New Task Sequence for Windows 10 Pro
        Import-MDTTaskSequence -path "DS001:\Task Sequences\Windows 10 Gold Image" -Name "Windows 10 Pro Gold Image" -Template "Client.xml" -Comments "" -ID $tsID -Version "1.0" -OperatingSystemPath "DS001:\Operating Systems\Windows 10\Windows 10 Pro in Windows 10 install.wim" -FullName "Windows User" -OrgName "Contoso" -HomePage "about:blank" -Verbose
        }

    $remDir = $mdtRoot.Split(":")[0]

    ############################################################################################
    #########################  SET CUSTOMSETTINGS AND BOOTSTRAP  ###############################
    ############################################################################################

    #Set custom settings 
    $cuSet = "$mdtRoot\Control\CustomSettings.ini"

    Set-Content -Path $cuSet -Value "[Settings]"
    Add-Content -Path $cuSet -Value "Priority=Model,ByVMType,ByLaptopType,ByDesktopType,DefaultGateway,Default"
    Add-Content -Path $cuSet -Value "Properties=MyCustomProperty"
    Add-Content -Path $cuSet -Value " "
    Add-Content -Path $cuSet -Value "[Model]"
    Add-Content -Path $cuSet -Value "Model=XPS 15 9550"
    Add-Content -Path $cuSet -Value " "
    Add-Content -Path $cuSet -Value "[XPS 15 9550]"
    Add-Content -Path $cuSet -Value 'OSDComputerName=XPS#right("%SerialNumber%",8)#'
    Add-Content -Path $cuSet -Value " "
    Add-Content -Path $cuSet -Value "[ByVMType]"
    Add-Content -Path $cuSet -Value "Subsection=VM-%IsVM%"
    Add-Content -Path $cuSet -Value " "
    Add-Content -Path $cuSet -Value "[VM-True]"
    Add-Content -Path $cuSet -Value 'OSDComputerName=VM#right("%SerialNumber%",8)#'
    Add-Content -Path $cuSet -Value " "
    Add-Content -Path $cuSet -Value "[ByLaptopType]"
    Add-Content -Path $cuSet -Value "Subsection=Laptop-%IsLaptop%"
    Add-Content -Path $cuSet -Value " "
    Add-Content -Path $cuSet -Value "[Laptop-True]"
    Add-Content -Path $cuSet -Value 'OSDComputerName=LP#right("%SerialNumber%",8)#'
    Add-Content -Path $cuSet -Value " "
    Add-Content -Path $cuSet -Value "[ByDesktopType]"
    Add-Content -Path $cuSet -Value "Subsection=Desktop-%IsDesktop%"
    Add-Content -Path $cuSet -Value " "
    Add-Content -Path $cuSet -Value "[Desktop-True]"
    Add-Content -Path $cuSet -Value 'OSDComputerName=DT#right("%SerialNumber%",10)#'
    Add-Content -Path $cuSet -Value " "
    Add-Content -Path $cuSet -Value "[DefaultGateway]"
    Add-Content -Path $cuSet -Value "$DHCPRouter=UK"
    Add-Content -Path $cuSet -Value "192.168.1.1=USA"
    Add-Content -Path $cuSet -Value " "
    Add-Content -Path $cuSet -Value "[UK]"
    Add-Content -Path $cuSet -Value "TimeZoneName=GMT Standard Time"
    Add-Content -Path $cuSet -Value "UILanguage=en-US"
    Add-Content -Path $cuSet -Value "UserLocale=en-GB"
    Add-Content -Path $cuSet -Value "SystemLocale=en-GB"
    Add-Content -Path $cuSet -Value "KeyboardLocale=en-GB;0809:00000809"
    Add-Content -Path $cuSet -Value "KeyboardLocalePE=en-GB;0809:00000809"
    Add-Content -Path $cuSet -Value " "
    Add-Content -Path $cuSet -Value "[USA]"
    Add-Content -Path $cuSet -Value "TimeZoneName=Pacific Standard Time"
    Add-Content -Path $cuSet -Value "UILanguage=en-US"
    Add-Content -Path $cuSet -Value "UserLocale=en-US"
    Add-Content -Path $cuSet -Value "SystemLocale=en-US"
    Add-Content -Path $cuSet -Value "KeyboardLocale=en-US;0409:00000409"
    Add-Content -Path $cuSet -Value "KeyboardLocalePE=en-US;0409:00000409"
    Add-Content -Path $cuSet -Value " "
    Add-Content -Path $cuSet -Value "[Default]"
    Add-Content -Path $cuSet -Value "_SMSTSOrgName=Tenaka: %TaskSequenceID%"
    Add-Content -Path $cuSet -Value " " 
    Add-Content -Path $cuSet -Value "'// Wizard Pages"
    Add-Content -Path $cuSet -Value "SkipWizard=NO"
    Add-Content -Path $cuSet -Value "SkipAppsOnUpgrade=YES"
    Add-Content -Path $cuSet -Value "SkipDeploymentType=YES"
    Add-Content -Path $cuSet -Value "SkipCapture=NO"
    Add-Content -Path $cuSet -Value "SkipComputerName=NO"
    Add-Content -Path $cuSet -Value "SkipDomainMembership=YES"
    Add-Content -Path $cuSet -Value "SkipUserData=YES"
    Add-Content -Path $cuSet -Value "SkipComputerBackup=YES"
    Add-Content -Path $cuSet -Value "SkipTaskSequence=NO"
    Add-Content -Path $cuSet -Value "SkipProductKey=YES"
    Add-Content -Path $cuSet -Value "SkipPackageDisplay=YES"
    Add-Content -Path $cuSet -Value "SkipLocaleSelection=YES"
    Add-Content -Path $cuSet -Value "SkipTimeZone=YES"
    Add-Content -Path $cuSet -Value "SkipApplications=YES"
    Add-Content -Path $cuSet -Value "SkipAdminPassword=YES"
    Add-Content -Path $cuSet -Value "SkipBitLocker=YES"
    Add-Content -Path $cuSet -Value "SkipSummary=YES"
    Add-Content -Path $cuSet -Value "SkipFinalSummary=YES"
    Add-Content -Path $cuSet -Value "SkipCredentials=YES"
    Add-Content -Path $cuSet -Value "SkipRoles=YES"
    Add-Content -Path $cuSet -Value " "
    Add-Content -Path $cuSet -Value "'// Build Settings - MDT Image Engineering"
    Add-Content -Path $cuSet -Value "OSInstall=Y"
    Add-Content -Path $cuSet -Value "SLShare=\\$IPAddress\logs$"
    Add-Content -Path $cuSet -Value "DeploymentType=NEWCOMPUTER"
    Add-Content -Path $cuSet -Value "'//JoinWorkgroup=WORKGroup"
    Add-Content -Path $cuSet -Value 'BackupFile = %TaskSequenceID%-#day(date)&"-"&month(date)&"-"&year(date)#.wim'
    Add-Content -Path $cuSet -Value "ComputerBackupLocation=\\$IPAddress\Captures$"
    Add-Content -Path $cuSet -Value "DoCapture=NO"
    Add-Content -Path $cuSet -Value "HideShell=NO"
    Add-Content -Path $cuSet -Value "TaskSequenceID=$tsID"
    Add-Content -Path $cuSet -Value "FinishAction=REBOOT"
    Add-Content -Path $cuSet -Value " "
    Add-Content -Path $cuSet -Value "OrgName=Contoso Net"
    Add-Content -Path $cuSet -Value "AdminPassword=SuperComplex;)"
    Add-Content -Path $cuSet -Value "AreaCode=020"
    Add-Content -Path $cuSet -Value "CountryCode=44"
    Add-Content -Path $cuSet -Value "Dialing=TONE"
    Add-Content -Path $cuSet -Value "LongDistanceAccess=1"
    Add-Content -Path $cuSet -Value "BitsPerPel=32"
    Add-Content -Path $cuSet -Value "VRefresh=60"
    Add-Content -Path $cuSet -Value "XResolution=1"
    Add-Content -Path $cuSet -Value "YResolution=1"
    Add-Content -Path $cuSet -Value " "
    Add-Content -Path $cuSet -Value "'//Capture Credentials"
    Add-Content -Path $cuSet -Value "'//UserID=Domain\$mdtUser"
    Add-Content -Path $cuSet -Value " "
    Add-Content -Path $cuSet -Value "UserID=$mdtUser"
    Add-Content -Path $cuSet -Value "UserPassword=$svcPass"
    Add-Content -Path $cuSet -Value " " 
    Add-Content -Path $cuSet -Value "'//MDT Monitoring and Update Server"
    Add-Content -Path $cuSet -Value "EventService=http://$IPAddress:9800"
    Add-Content -Path $cuSet -Value "'//WSUSServer=http://192.168.0.85:8530"
    Add-Content -Path $cuSet -Value " "

    #Update BootStrap.ini
    $bootStrap = "$mdtRoot\Control\Bootstrap.ini"

    Set-Content -Path $bootStrap -Value "SkipBDDWelcome=YES"
    Add-Content -Path $bootStrap -Value "DeployRoot=\\$IPAddress\$mdtShRoot"
    Add-Content -Path $bootStrap -Value "UserDomain=contoso.net"
    Add-Content -Path $bootStrap -Value "UserID=$mdtUser"
    Add-Content -Path $bootStrap -Value "UserPassword=$svcPass"

    ############################################################################################
    ######################################  THE END  ###########################################
    ############################################################################################
}
