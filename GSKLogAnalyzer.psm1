function Select-GSKFirewallLog
{
    <#
.SYNOPSIS
This function takes the log from the Firewall and displays sorted data
.DESCRIPTION
This function takes the log from the Firewall and displays sorted data depending on criterias (see Parameters)
It removes unwanted data and groups the remainings logs if the source IP, destination IP, Source application and destination port are the same. 
I also displays the range of source port

.PARAMETER LogPath
It's the path to the log file. The file must be a CSV file

.PARAMETER DateTime
This parameter allow you to select a specific interval of recorded data. The format must be HH:mm. 
If you use this parameter, you HAVE to use the parameter Interval 
.PARAMETER Interval
If you use DateTime, this parameter is mandatory. It creates hour minimum and hour maximum for grouping the data. 
The interval is in minutes

.PARAMETER DestinationPort
Accept a comma separated list of port numbers. It will remove any log that is not for this(ese) destination port(s)

.EXAMPLE
Select-GSKFirewallLog -LogPath 'c:\myexample.csv'
This will take the log and analyze the entire file. 

.EXAMPLE
Select-GSKFirewallLog -LogPath 'c:\myexample.csv' -DateTime '4:52' -Interval 4
This will take the log "myexample.csv" and analyze the log from 4:52AM to 4:56AM 

.EXAMPLE
Select-GSKFirewallLog -LogPath 'c:\myexample.csv' -DestinationPort 53,135,88
This will take the log "myexample.csv" and retrieve the logs for port 53, 135 and 88. 
You can combine the interval and the port numbers
#>
    [CmdletBinding()]
    param (
        [parameter(mandatory = $true, ValueFromPipeline = $true)]
        [ValidateScript( { 
                if ($_ -notmatch "\.csv")
                {
                    throw "The file specified is not a CSV file"
                }
                return $true
            })]
        [System.IO.FileInfo]
        $LogPath,        
        [Parameter(ParameterSetName = "Interval", HelpMessage = "format of time HH:MM")]
        [ValidateScript( {
                if ((get-date $_).ToShortTimeString() -notmatch "\A([0-9]|0[0-9]|1[0-9]|2[0-3]):([0-5][0-9]|[0-9])\Z")
                {
                    throw "The time format is not supporte! It must be HH:MM"
                }
                return $true
            })]
        [datetime]
        $DateTime,
        [int[]]
        $DestinationPort,
        [switch]
        $RemoveInfraPort  
    )
    dynamicparam
    {
        if ($PSBoundParameters.ContainsKey('DateTime'))
        {
            $IntervalAttribute = New-Object System.Management.Automation.ParameterAttribute
            $IntervalAttribute.Mandatory = $true
            $IntervalAttribute.HelpMessage = "Number of minutes after the time chosen in datetime parameter"
            $IntervalAttribute.ParameterSetName = "Interval"
            $attributeCollection = new-object System.Collections.ObjectModel.Collection[System.Attribute]
            $attributeCollection.Add($IntervalAttribute)
            $intervalParam = New-Object System.Management.Automation.RuntimeDefinedParameter('interval', [int], $attributeCollection)
            $paramDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
            $paramDictionary.Add('interval', $intervalParam)
            return $paramDictionary
        }
    }
    process
    {
        if ($RemoveInfraPort)
        {
            $RemoveInfraPort = $true
        }
        else 
        {
            $RemoveInfraPort = $false
        }

        try
        {
            $GskFirewallLog = Import-GSKFirewallLog -Path $LogPath -ErrorAction Stop



            if ($PSBoundParameters.ContainsKey('DestinationPort') -and $PSBoundParameters.ContainsKey('DateTime') )
            {
                Write-Verbose "analyzing log with Destination port(s), and a time interval"
                $GskFirewallLog = remove-GSKUnwantedFirewallLog -FirewallLog $GskFirewallLog -DestinationPort $DestinationPort -DateTime $DateTime -Interval $interval -RemoveInfraPort:$RemoveInfraPort
            }
            elseif ($PSBoundParameters.ContainsKey('DestinationPort'))
            {
                Write-Verbose "analyzing log with Destination port(s)"
                $GskFirewallLog = remove-GSKUnwantedFirewallLog -FirewallLog $GskFirewallLog -DestinationPort $DestinationPort -RemoveInfraPort:$RemoveInfraPort
            }
            elseif ($PSBoundParameters.ContainsKey('DateTime'))
            {
                Write-Verbose "analyzing log with a time interval"
                $GskFirewallLog = remove-GSKUnwantedFirewallLog -FirewallLog $GskFirewallLog -DateTime $DateTime -Interval $interval -RemoveInfraPort:$RemoveInfraPort
            }
            else
            {
                Write-Verbose "analyzing all log"
                $GskFirewallLog = remove-GSKUnwantedFirewallLog -FirewallLog $GskFirewallLog -RemoveInfraPort:$RemoveInfraPort
            }

    
            if ($GskFirewallLog.count -gt 0)
            {
                Group-GSKFirewallLog -FirewallLog $GskFirewallLog | Select-Object 'Source address', 'Destination address', 'Application', 'Destination Port', 'IP Protocol', 'Range'
            }
            else
            {
                Write-Output "there is no data to display"
            }   
        }#end Try
        catch
        {
            $message = $_.Exception.Message 
            Write-Output $message

        }#end Catch        
    }#end Process
}#end Function
   
function Import-GSKFirewallLog
{
    <#
.SYNOPSIS
Import selected column of CSV file
.DESCRIPTION
The function importh the Firewall Log and select only the necessary column
It also transform the Generate Time column in a usable DateTime format
It out an Array ready for use
.PARAMETER Path
This is the Path to the CSV file
#>
    [CmdletBinding()]
    param (
        [parameter(mandatory = $true, ValueFromPipeline = $true)]
        [System.IO.FileInfo]
        $Path
    )

    Write-Verbose "Importing CSV File"
    $OutArray = import-csv -Path $Path
    
    Write-Verbose "checking if the necessary columns are there" 
    $header = $OutArray | Get-Member | Select-Object -ExpandProperty "name"
    $MandatoryColumn = 'Generate Time', 'Source address', 'Destination address', 'Application', 'Source Port', 'Destination Port', 'IP Protocol'
    $MatchedColumnCount = 0

    foreach ($Elem in $MandatoryColumn)
    {
        foreach ($columnName in $header)
        {
            if ($Elem -eq $columnName)
            {
                $MatchedColumnCount = $MatchedColumnCount + 1
                break
            }
        }
    }
    
    If ($MatchedColumnCount -eq 7)
    {
        Write-Verbose "All the necessary columns are found in the file"
        Write-Verbose "replacing DateTime with only the timeStamp"
        foreach ($line in $OutArray)
        {   
            $line.'Generate Time' = ([datetime]::ParseExact($line.'Generate Time', 'dd/MM/yyyy HH:mm', $null)).ToShortTimeString()
        }

        $OutArray | Select-Object 'Generate Time', 'Source address', 'Destination address', 'Application', 'Source Port', 'Destination Port', 'IP Protocol'
    }
    else
    {
        Throw "The CSV doesn't contain all the necessary columns for this analyzer"
    }
}


function remove-GSKUnwantedFirewallLog
{
    [CmdletBinding()]
    param (
        
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [array]
        $FirewallLog,
        [datetime]
        $DateTime,
        [int]
        $Interval,
        [int[]]
        $DestinationPort,
        [switch]
        $RemoveInfraPort        
    )
    $OutArray = $FirewallLog
    if ($RemoveInfraPort)
    {
        Write-Verbose "Removing infra Port"
        $infraPort = 53, 67, 68, 80, 88, 123, 135, 137, 138, 139, 389, 443, 445, 2967, 8014
        $OutArray = @()

        foreach ($log in $FirewallLog)
        {
            $match = $false
            foreach ($port in $infraPort)
            {
                if ($port -eq $log.'Destination Port')
                {
                    $match = $true
                    break
                }
            }

            if (!$match)
            {
                $OutArray += $log
            }
        }
        $FirewallLog = $OutArray
    }

    if ($PSBoundParameters.ContainsKey('DestinationPort'))
    {
        Write-Verbose "selecting requested ports from the log"
        $OutArray = @()
        foreach ($port in $DestinationPort)
        {
            foreach ($log in $FirewallLog)
            {
                if ($port -eq $log.'Destination Port')
                {
                    $OutArray += $log
                }#if $port
            }#foreach log
        }#foreach port
        $FirewallLog = $OutArray
    }#If destinationport exist

    
    if ($PSBoundParameters.ContainsKey('DateTime'))
    {
        Write-Verbose "selecting requested timespan from the log"        
        $OutArray = @()
        $min = (get-date $DateTime).ToShortTimeString()
        $ts = New-TimeSpan -Minutes $Interval
        $max = ((get-date $DateTime) + $ts).ToShortTimeString()

        foreach ($log in $FirewallLog)
        {
            if (!($log.'Generate Time' -ge $min -and $log.'Generate Time' -le $max))
            {
                $OutArray += $log
            }
        }#foreach
    }#if datetime exist
    
    $OutArray
}#endFunction

function Group-GSKFirewallLog
{
    <#
.SYNOPSIS
Sort the Firewall logs received by GSK Corp
.DESCRIPTION
This command will take a CSV of the firewall logs and group them by destination port
It will also show the max and min source port used to access the destination port. 
.PARAMETER ServiceName

.EXAMPLE
Group-GSKFirewallLog -Path $CVSFile
This will take the all file and group every ports from anytime
#>
    [CmdletBinding()]

    param (        
        [Parameter(mandatory = $true)]    
        [array]
        $FirewallLog            
    )
    Write-Verbose -Message "Group-GSKFirewallLog has started"
    $OutArray = @()
    Foreach ($log in $FirewallLog)
    {
        
        $log | Add-Member -Type NoteProperty -Name "minPort" -Value $log."Source Port"
        $log | Add-Member -Type NoteProperty -Name "maxPort" -Value $log."Source Port"
        $log | Add-Member -Type NoteProperty -Name "Range" -Value 0

        $match = $false
        if ($OutArray.Count -ne 0)
        { 
            Foreach ($Record in $outArray)
            {
                if (($log."Source address" -eq $Record."Source address") -and 
                    ($log."Destination address" -eq $Record."Destination address") -and
                    ($log."Application" -eq $Record."Application") -and
                    ($log."Destination Port" -eq $Record."Destination Port"))
                {
                    $match = $true
                    break
                }#endIf
            }#endForeach $record
            If ($match -eq $false)
            {
                $OutArray += $log
            }
            else
            {
                if ($record."minPort" -gt $log."Source Port")
                {
                    $Record."minPort" = $log."Source Port"
                }
                if ($Record."maxPort" -lt $log."Source Port")
                {
                    $Record."maxPort" = $log."Source Port"
                }                
            }
        }#endif(count -ne 0)
        else
        {
            Write-Verbose "populating log"
            $OutArray += $log
        }
    }#end foreachLog$

    foreach ($log in $OutArray)
    {
        $log.'Range' = $log.'minPort' + ' - ' + $log.'maxPort'
    }
    Write-Verbose "The grouping has been done"
    $outArray
}#endFunction