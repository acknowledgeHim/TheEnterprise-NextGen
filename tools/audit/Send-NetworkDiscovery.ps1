<#
.SYNOPSIS
    Scan an entire subnet for computers doing a reverse lookup, any Windows
    machines that are found will get basic information about them.  Also
    gets basic Active Directory information.
.DESCRIPTION
    Meant for the on the go consultant, or anyone who just wants to understand
    their network better.  Run the script, sit back and wait for the email which
    includes HTML reports on all workstations, servers and IP list (only as good
    as the reverse DNS).

    It will also email you the raw data in XML format which can easily be inputed
    using Import-CliXml and than manipulated using Powershell.

    ** It is hightly recommended that you edit the PARAM section to match your needs,
    especially parameters.  **

    For security reasons, you cannot specify the password in the script but must
    wait for it to prompt you.

.PARAMETER Company
    Name of the Company being scanned.  This is only used in the header of the
    reports.
.PARAMETER Network
    IP address of the network you are on.  Can be any valid IP address in the range.
    I.E.  192.168.0.5.  If you do not provide the network information the script
    will look at the workstations IP information and use that.
.PARAMETER SubnetMask
    Subnet mask of the network you wish to scan.  It is also possible to use a
    custom subnet mask to only scan a few devices, if you know how to change that.
    I.E.  255.255.255.0.  If you do not provide the subnet mask information the script
    will look at the workstations IP information and use that.
.PARAMETER NoNetwork
    Use this switch to instruct the script to NOT scan all IP addresses
.PARAMETER NoADInformation
    Use this switch to instruct the script to NOT scan for Active Directory information.
.PARAMTER MaxThreads
    Maximum number of concurrent threads that can run on the PC.  Bigger workstations
    can run more threads, but if you run too many threads you can actually slow the
    process down.
.INPUTS
    None
.OUTPUTS
    ND.HTML - HTML report of all workstations and servers as well as a IP listing.
    AD.HTML - HTML report of basic Active Directory information.
    ND.XML - raw data of all workstations, servers and IP addresses
    AD.XML - raw Active Directory information
.EXAMPLE
    .\Send-NetworkDiscovery.ps1

    Accepts all defaults and runs on the local IP subnet.  Assuming the network is
    192.168.0.0 with a mask of 255.255.255.0 all IP address from 192.168.0.1 to
    192.168.0.254 will be scanned.  Email will be sent to the default user
    (you@yourdomain.com) and relayed through GMail using the user account you@gmail.com.
    Script will prompt for password.
.EXAMPLE
    .\Send-NetworkDiscovery.ps1 -Company "My Company" -To "me@mycompany.com" -MailAuthUser "me@gmail.com"

    Scan entire network, email to Me@mycompany.com using me@gmail.com to authenticate
    against the default smtp.gmail.com server.

.EXAMPLE
    .\Send-NetworkDiscovery.ps1 -NoAD

    Only scan the network, do not scan for Active Directory information.
.NOTES
    Author:            Martin Pugh
    Twitter:           @thesurlyadm1n
    Spiceworks:        Martin9700
    Blog:              www.thesurlyadmin.com

    Changelog:
       1.0             Initial Release
.LINK
    http://community.spiceworks.com/scripts/show/1907-send-networkdiscovery-network-discovery
#>
[CmdletBinding()]
Param (
    [Parameter(Mandatory=$true)]
    [string]$Company,
    [Alias("IP")]
	[string]$Network,
    [Alias("Mask")]
	[string]$SubnetMask,
    [switch]$NoNetwork,
    [Alias("NoAD")]
	[switch]$NoADInformation,
    [int]$Port = 587,
    [int]$MaxThreads = 10
)


#region Functions
#Awesome IP range functions from Chris Dent
#Read his blog:  http://www.indented.co.uk/

Function Get-NetworkRange {
    Param (
        [String]$IP,
        [String]$Mask
    )
    Write-Output $IP
    If ($IP.Contains("/"))
    {   $Temp = $IP.Split("/")
        $IP = $Temp[0]
        $Mask = $Temp[1]
    }
    if ($IP.Contains(" ")) {
       $Temp = $IP.split(" ")
       $IP = $Temp[0]
    }
    Write-Output $IP

    if ($Mask.Contains(" ")) {
        $Temp = $Mask.split(" ")
        $Mask = $Temp[0]
    }
    If (!$Mask.Contains("."))
    {   $Mask = ConvertTo-Mask $Mask
    }

    $DecimalIP = ConvertTo-DecimalIP $IP
    $DecimalMask = ConvertTo-DecimalIP $Mask

    $Network = $DecimalIP -BAnd $DecimalMask
    $Broadcast = $DecimalIP -BOr ((-BNot $DecimalMask) -BAnd [UInt32]::MaxValue)

    For ($i = $($Network + 1); $i -lt $Broadcast; $i++) {
        ConvertTo-DottedDecimalIP $i
    }
}  #End Get-NetworkRange

Function ConvertTo-DottedDecimalIP {
  <#
    .Synopsis
      Returns a dotted decimal IP address from either an unsigned 32-bit integer or a dotted binary string.
    .Description
      ConvertTo-DottedDecimalIP uses a regular expression match on the input string to convert to an IP address.
    .Parameter IPAddress
      A string representation of an IP address from either UInt32 or dotted binary.
  #>

  [CmdLetBinding()]
  Param(
    [Parameter(Mandatory = $True, Position = 0, ValueFromPipeline = $True)]
    [String]$IPAddress
  )

  Process {
    Switch -RegEx ($IPAddress) {
      "([01]{8}\.){3}[01]{8}" {
        Return [String]::Join('.', $( $IPAddress.Split('.') | ForEach-Object { [Convert]::ToUInt32($_, 2) } ))
      }
      "\d" {
        $IPAddress = [UInt32]$IPAddress
        $DottedIP = $( For ($i = 3; $i -gt -1; $i--) {
          $Remainder = $IPAddress % [Math]::Pow(256, $i)
          ($IPAddress - $Remainder) / [Math]::Pow(256, $i)
          $IPAddress = $Remainder
         } )

        Return [String]::Join('.', $DottedIP)
      }
      default {
        Write-Error "Cannot convert this format"
      }
    }
  }
}  #End ConvertTo-DottedDecimalIP

Function ConvertTo-DecimalIP {
  <#
    .Synopsis
      Converts a Decimal IP address into a 32-bit unsigned integer.
    .Description
      ConvertTo-DecimalIP takes a decimal IP, uses a shift-like operation on each octet and returns a single UInt32 value.
    .Parameter IPAddress
      An IP Address to convert.
  #>

  [CmdLetBinding()]
  Param(
    [Parameter(Mandatory = $True, Position = 0, ValueFromPipeline = $True)]
    [Net.IPAddress]$IPAddress
  )

  Process {
    $i = 3; $DecimalIP = 0;
    $IPAddress.GetAddressBytes() | ForEach-Object { $DecimalIP += $_ * [Math]::Pow(256, $i); $i-- }

    Return [UInt32]$DecimalIP
  }
}  #End ConvertTo-DecimalIP


#Set Alternating Rows in HTML tables
Function Set-AlternatingRows {
    [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
            [object[]]$HTMLDocument,

            [Parameter(Mandatory=$True)]
            [string]$CSSEvenClass,

            [Parameter(Mandatory=$True)]
            [string]$CSSOddClass
        )
     Begin {
          $ClassName = $CSSEvenClass
     }
     Process {
          [string]$Line = $HTMLDocument
          If ($Line.Contains("<tr>"))
          {
               $Line = $Line.Replace("<tr>","<tr class=""$ClassName"">")
               If ($ClassName -eq $CSSEvenClass)
               {     $ClassName = $CSSOddClass
               }
               Else
               {     $ClassName = $CSSEvenClass
               }
          }
          $Line = $Line.Replace("[return]","<br>")
          Return $Line
     }
} #End Set-AlternatingRows


Function ConvertTo-OrderedList
{   Param (
        [array]$List
    )

    $Fragment = "<ul>"
    ForEach ($Line in $List)
    {   $Fragment += "<li>$Line</li>`n"
    }
    $Fragment += "</ul>"
    Return $Fragment
} #End ConvertTo-OrderedList


Function ConvertTo-ArrayToString
{   Param (
        [String[]]$Array
    )
    For ($i = 0 ; $i -le $Array.Count - 1; $i ++ ) {
        If ($i -eq 0)
        {   [string]$Result = "$($Array[0])"
        }
        Else
        {   $Result += "[return]$($Array[$i])"
        }
    }
    Return $Result
} #End ConvertTo-ArrayToString

#endregion Functions

#Region GetComputerInfo Scriptblock
$GetComputerInfo = {
    Param (
        [string]$IP
    )

    Function PrepSize
    {   Param (
		    [double]$Size
	    )
	    If ($Size -ge 1000000000)
    	{	$ReturnSize = "{0:N2} GB" -f ($Size / 1GB)
	    }
	    Else
    	{	$ReturnSize = "{0:N2} MB" -f ($Size / 1MB)
	    }
    	Return $ReturnSize
    }

    #Reverse Ping to get DNS name (if exists)
    $Ping = Get-WMIObject Win32_PingStatus -Filter "Address = '$IP' AND ResolveAddressNames = TRUE"
    If ($Ping.StatusCode -eq 0)
    {   $ComputerName = $Ping.ProtocolAddressResolved
        $WMI = Get-WmiObject Win32_OperatingSystem -ComputerName $ComputerName
        If ($WMI)
        {   #Get OS Version
            $OS = $WMI.Caption
            $OSVersion = $WMI.Version
            $ServicePack = "$($WMI.ServicePackMajorVersion).$($WMI.ServicePackMinorVersion)"

            #Get CPU Information
            $WMI = Get-WmiObject Win32_Processor -ComputerName $ComputerName
            $NumCPUS = @($WMI).Count
            $CPU = @($WMI)[0].Name

            #Get Chassis Information
            $WMI = Get-WmiObject Win32_BaseBoard -ComputerName $ComputerName
            $MakeModel = "$($WMI.Manufacturer)/$($WMI.Model)"
            $ServiceTag = $WMI.Product
            $SerialNumber = $WMI.SerialNumber

            #Get Memory Information
            $WMI = Get-WmiObject Win32_PhysicalMemory -ComputerName $ComputerName
            $Memory = PrepSize ( ($WMI | Measure-Object -Property Capacity -Sum).Sum )

            #Get Logical Disk Information
            $WMI = @(Get-WmiObject Win32_LogicalDisk -Filter "DriveType = 3" -ComputerName $ComputerName)
            $Drives = @()
            ForEach ($Drive in $WMI)
            {   $Capacity = PrepSize ($Drive.Size)
                $FreeSpace = PrepSize ($Drive.FreeSpace)
                $Drives += "$($Drive.DeviceID) $Capacity ($FreeSpace Free)"
            }
            $Status = "Successful"
        }
        Else
        {   If ($ComputerName -eq $IP)
            {   $ComputerName = "Unknown"
            }
            $Status = "Ping successful, no WMI response"
        }
    }
    Else
    {   $ComputerName = "None"
        $Status = "No Response to Ping"
    }
    New-Object PSObject -Property @{
        'Computer Name' = $ComputerName
        Status = $Status
        IP = $IP
        OS = $OS
        'OS Version' = $OSVersion
        'OS Service Pack' = $ServicePack
        CPU = $CPU
        'Number of CPUs' = $NumCPUS
        'Make/Model' = $MakeModel
        'Service Tag' = $ServiceTag
        'Serial Number' = $SerialNumber
        Memory = $Memory
        'Hard Drives' = $Drives
    }
}
#EndRegion

cls
$Attachments = @()
$MyPath = Split-Path $MyInvocation.MyCommand.Path
If (-not $NoNetwork)
{   $HTMLCSS = @"
<style>
TABLE {border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;}
TH {border-width: 1px;padding: 3px;border-style: solid;border-color: black;background-color: #6495ED;}
TD {border-width: 1px;padding: 3px;border-style: solid;border-color: black;}
.odd  { background-color:#ffffff; }
.even { background-color:#dddddd; }
</style>
<title>
Network Information for $Company
</title>
"@

    #Clean out any old jobs, if any
    ForEach ($Job in (Get-Job))
    {   Remove-Job $Job
    }

    #Get IP Address and Subnetmask if not specified in Parameters
    $IPInfo = @(Get-WMIObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled='TRUE'")
    If (-not $Network)
    {   $Network = $IPInfo[0].IPAddress
    }
    If (-not $SubnetMask)
    {   $SubnetMask = $IPInfo[0].IPSubnet
    }

    #Calculate IP range and submit GetComputerInfo scriptblock as background jobs
    $Range = Get-NetworkRange $Network $SubnetMask
    $Submitted = 0
    ForEach ($IPAddress in $Range)
    {   $JobCount = @(Get-Job -State Completed).Count
        Write-Progress -Id 1 -Activity "Gathering Computer Information..." -Status "Submitting threads: $($Range.Count - $Submitted)" -PercentComplete ($JobCount / $Range.Count * 100)
        While (@(Get-Job | Where { $_.State -ne "Completed" }).Count -ge $MaxThreads) {
            Write-Verbose "Waiting for open thread...($MaxThreads Maximum)"
            Start-Sleep -Seconds 3
        }
        $Job = Start-Job -ScriptBlock $GetComputerInfo -ArgumentList $IPAddress
        $Submitted ++
        Write-Verbose ($Job | Select Id,Name,State,HasMoreData)
    }

    #Wait for all jobs to complete
    Do {
        $JobCount = @(Get-Job -State Completed).Count
        Write-Progress -Id 1 -Activity "Gathering Computer Information..." -Status "Waiting for background jobs to finish: $($Range.Count - $JobCount)" -PercentComplete ($JobCount / $Range.Count * 100)
        Write-Verbose "Waiting for background jobs..."
        Start-Sleep -Seconds 3
    } While (@(Get-Job | Where { $_.State -ne "Completed" }).Count -ne 0)
    Write-Progress -Id 1 -Activity "Gathering Computer Information..." -Status "Background Jobs Completed" -PercentComplete 100
    Write-Verbose "All jobs completed!"

    #Now retrieve information from the jobs
    $Data = @()
    $Data = ForEach ($Job in (Get-Job))
    {   Receive-Job $Job
        Remove-Job $Job | Out-Null
    }
    $WSFragment = $Data | Where { $_.OS -notlike "*Server*" -and $_.OS -ne $null } | Select 'Computer Name',OS,'OS Service Pack','Make/Model','Serial Number','Service Tag',IP,'Number of CPUs',Memory,
        @{Label="Hard Drives";Expression={ConvertTo-ArrayToString $_.'Hard Drives'}} | ConvertTo-Html -Fragment | Set-AlternatingRows -CSSEvenClass even -CSSOddClass odd
    $IPFragment = $Data | Select IP,'Computer Name' | ConvertTo-Html -Fragment | Set-AlternatingRows -CSSEvenClass even -CSSOddClass odd
    $HTML = $Data | Where { $_.OS -like "*Server*" } | Select 'Computer Name',OS,'OS Service Pack','Make/Model','Serial Number','Service Tag',IP,'Number of CPUs',Memory,
        @{Label="Hard Drives";Expression={ConvertTo-ArrayToString $_.'Hard Drives'}}
    $HTML = $HTML | ConvertTo-Html -Head $HTMLCSS -PreContent "<h2>Network Discovery for $Company</h2><br><h3>Server List</h3>" -PostContent "<br><h3>Workstation List</h3><br>$WSFragment<br><h3>IP List</h3><br>$IPFragment"
    $HTML | Set-AlternatingRows -CSSEvenClass even -CSSOddClass odd | Out-File "$MyPath\nd.html"
    $Data | Export-Clixml "$MyPath\Data.xml"
    $Attachments += "$MyPath\nd.html","$MyPath\Data.xml"
}

If (-not $NoADInformation)
{   #Get AD Information
    $WSHNetwork = New-Object -ComObject "Wscript.Network"
    $Domain = $WSHNetwork.UserDomain
    $Root = [ADSI] "LDAP://RootDSE"
    $Config = $Root.ConfigurationNamingContext

    #Get Sites
    $SitesDN = "LDAP://CN=Sites,$Config"
    $Sites = ForEach ($Site in ($([ADSI]$sitesDN).PSBase.Children | Where { $_.objectClass -eq "site" }))
    {   $Site.Name
    }

    #Get Domain Controllers and Global Catalogs
    $DomainControllers = @()
    $DomainControllersSites = @()
    $GC = @()
    $DCs = ([System.DirectoryServices.ActiveDirectory.DomainController]::FindAll((New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain",$Domain))))
    ForEach ($DC in $DCs)
    {   ForEach ($Role in $DC.Roles)
        {   Switch ($Role)
            {   "SchemaRole" {$FSMOSchema = $DC.Name}
                "NamingRole" {$FSMONaming = $DC.Name}
                "PdcRole" {$FSMOPDC = $DC.Name}
                "RidRole" {$FSMORID = $DC.Name}
                "InfrastructureRole" {$FSMOInfrastructure = $DC.Name}
            }
        }
        $DomainControllers += $DC.Name
        $DomainControllersSites += $DC.SiteName
        If ($DC.IsGlobalCatalog())
        {   $GC += $DC.Name
        }
    }
    $ActiveDirectory = New-Object PSObject -Property @{
        Domain = $Domain
        Sites = $Sites
        'Domain Controllers' = $DomainControllers
        'DC Site' = $DomainControllersSites
        'Global Catalogs' = $GC
        'Forest Schema Master' = $FSMOSchema
        'Forest Naming Master' = $FSMONaming
        'Domain PDC Emulator' = $FSMOPDC
        'Domain RID Master' = $FSMORID
        'Domain Infrastructure Master' = $FSMOInfrastructure
    }
    $DCs = @()
    For ($i = 0; $i -lt $DomainControllers.Count; $i ++ )
    {   $DCs += New-Object PSObject -Property @{
            Name = $DomainControllers[$i]
            Site = $DomainControllersSites[$i]
            'IP Address' = (Test-Connection $DomainControllers[$i] -Count 1).IPv4Address.IPAddressToString
        }
    }
    #Build the HTML
    $SiteFragment = ConvertTo-OrderedList ($Sites | Sort)
    $DCFragment = $DCs | Select Name,Site,'IP Address' | Sort Site,Name | ConvertTo-Html -Fragment | Set-AlternatingRows -CSSEvenClass even -CSSOddClass odd
    $GCFragment = ConvertTo-OrderedList ($GC | Sort)

    $Body = @"
<html>
<head>
<style type='text/css'>
body {background-color:#DCDCDC;font-size:20px;}
b {font-size:24px;}
TABLE {border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;font-size:20px;}
TH {border-width: 1px;padding: 3px;border-style: solid;border-color: black;background-color: #6495ED;width:300px;}
TD {border-width: 1px;padding: 3px;border-style: solid;border-color: black;}
</style>
<title>
Active Directory Information for $Company
</title>
</head>
<body>
<h2>Active Directory Information for $Company</h2>
<br>
<b>Domain Name:</b> $domain<br>
<br>
<p><b>AD Sites</b>
$SiteFragment
<br>
<b>Domain Controllers</b><p>
$DCFragment
<br>
<br>
<b>FSMO Role Holders</b><p>
<table>
<th>Role</th><th>Holder</th>
<tr><td>Forest-wide Schema Master</td><td>$FSMOSchema</td>
<tr><td>Forest-wide Domain Naming Master</td><td>$FSMONaming</td>
<tr><td>Domain's PDC Emulator</td><td>$FSMOPDC</td>
<tr><td>Domain's RID Master</td><td>$FSMORID</td>
<tr><td>Domain's Infrastructure Master</td><td>$FSMOInfrastructure</td>
</table>
<br>
<br>
<b>Global Catalogs</b>
$GCFragment
</body>
</html>
"@
    $Body | Out-File "$MyPath\ad.html"
    $ActiveDirectory | Export-Clixml "$MyPath\AD.xml"
    $Attachments += "$MyPath\ad.html","$MyPath\AD.xml"
}

