<#
#>
[cmdletbinding()]
param(
  [string]$logFilePath
)

$global:mpSigStubLogResults = [ordered]@{}
$global:mpSigStubLogResult = [ordered]@{}
$global:mpSigStubLogResultObject = [ordered]@{}
$recordSeparator = '--------------------------------------------------------------------------------'
$recordPropertyPattern = '={10,}? (?<propertyName>\w+) ={10,}?'
$guidPattern = '\w{8}-\w{4}-\w{4}-\w{4}-\w{12}'
$startOfLinePattern = '^'
$global:records = [collections.arrayList]::new()

function main() {
  try {

    if (!(Test-Path $logFilePath)) {
      Write-Host "File not found: $logFilePath"
      return 1
    }
    $global:mpSigStubLogResults = Read-Records $logFilePath

    return $global:mpSigStubLogResults
  }
  catch {
    write-verbose "variables:$((get-variable -scope local).value | convertto-json -WarningAction SilentlyContinue -depth 2)"
    write-host "exception::$($psitem.Exception.Message)`r`n$($psitem.scriptStackTrace)" -ForegroundColor Red
    return 1
  }
}

function Add-ComponentsToResult([collections.arrayList]$components, [collections.specialized.orderedDictionary]$resultRecord) {
  # components have a name, optional value (value can also be split into signature and version)
  foreach ($component in $components) {
    if ($component.Signature) {
      if ($null -ne $resultRecord[$component.FileName].Signature) {
        $resultRecord[$component.FileName].Signature = $component.Signature
      }
      else {
        $resultRecord[$component.FileName] = $component.Signature
      }
    }

    if ($component.Version) {
      if ($null -ne $resultRecord[$component.FileName].Version) {
        $resultRecord[$component.FileName].Version = $component.Version
      }
      else {
        $resultRecord[$component.FileName] = $component.Version
      }
    }
  }

  return $resultRecord
}

function Find-Match([string]$line, [string]$pattern, [bool]$ignoreCase = $true, [Text.RegularExpressions.RegexOptions]$regexOptions = [Text.RegularExpressions.RegexOptions]::None) {
  Write-Verbose "Find-Match([string]$line, [string]$pattern, [bool]$ignoreCase, [Text.RegularExpressions.RegexOptions]$regexOptions)"
  if (!$line) {
    Write-Error "Regex-Match: No line provided"
    throw
    return $null
  }
  if (!$pattern) {
    Write-Error "Regex-Match: No pattern provided"
    throw
    return $null
  }

  if ($ignoreCase) {
    $regexOptions = $regexOptions -bor [Text.RegularExpressions.RegexOptions]::IgnoreCase
  }
  
  Write-Verbose "Regex-Match: [regex]::Match($line, $pattern, $regexOptions)"
  $regexMatch = [regex]::Match($line, $pattern, $regexOptions)

  if ($regexMatch.Success) {
    if ($regexMatch.Groups.Count -eq 1 -and [string]::IsNullOrEmpty($regexMatch.Groups[0].Value)) {
      Write-Verbose "Regex-Match: No groups found. line: $line pattern: $pattern"
      return $null
    }

    # create key value pair
    $groups = @{}
    foreach ($group in $regexMatch.Groups) {
      Write-Verbose "Regex-Match: Group: $($group.Name) = $($group.Value)"
      [void]$groups.Add($group.Name.Trim(), $group.Value.Trim())
    }

    return $groups
  }

  Write-Verbose "Regex-Match: No match found for pattern: $pattern"
  return $null
}

function Format-ComponentResults([collections.arrayList]$files, [string]$pattern, [switch]$formatName) {
  Write-Verbose "Format-ComponentResults([collections.arrayList]$($files.Count), [string]$pattern, [switch]$formatName)"
  $fileList = [collections.arrayList]::new()
  # look for files (names with . in it)
  $files = Read-PropertyNameValues -record $record -propertyName $pattern

  foreach ($file in $files) {
    $fileName = $file['propertyName']
    
    if ($formatName) {
      $fileName = $fileName.Replace(' ', '') 
    }
    
    $propertyValue = $file['propertyValue']
    if (!$fileName -or !$propertyValue) {
      continue
    }

    $componentValue = Find-Match -line $propertyValue -pattern '(?<Signature>[0-9A-Fa-f]{64}\s+)|(?<Version>[\d\.]+)'
    if ($componentValue -and $componentValue['Signature']) {
      [void]$fileList.Add([ordered]@{
          'FileName'  = $fileName
          'Signature' = $componentValue['Signature']
          'Version'   = $componentValue['Version']
        })
      continue
    }
    elseif ($componentValue -and $componentValue['Version']) {
      [void]$fileList.Add([ordered]@{
          'FileName'  = $fileName
          'Version' = $componentValue['Version']
        })
    }
    else {
      [void]$fileList.Add([ordered]@{
          'FileName'  = $fileName
          'Signature' = $propertyValue
        })
    }
  }
  return $fileList
}

function New-AccumulatePackagesRecord() {
  $record = [ordered]@{
    'PackageName' = ''
  }
  return $record
}

function New-PackagesDiscoveryRecord() {
  $record = [ordered]@{
    'Directory'         = ''
    'PackageIdentifier' = '' # guid
    'Files'             = @(
      [ordered]@{
        'FileName'  = ''
        'Signature' = ''
      }
    )
    'Engine'            = [ordered]@{
      'Version'   = ''
      'Signature' = ''
    }
    'ASBaseVDM'         = [ordered]@{
      'Version'   = ''
      'Signature' = ''
    }
    'AVBaseVDM'         = [ordered]@{
      'Version'   = ''
      'Signature' = ''
    }
    'ASDeltaVDM'        = [ordered]@{
      'Version'   = ''
      'Signature' = ''
    }
    'AVDeltaVDM'        = [ordered]@{
      'Version'   = ''
      'Signature' = ''
    }
  }
  return $record
}

function New-PatchApplicationRecord() {
  $record = [ordered]@{
    'Files' = @(
      [ordered]@{
        'FileName' = ''
        'Version'  = ''
      }
    )
  }
  return $record
}

function New-ProductSearchRecord() {
  $record = [ordered]@{
    'Product'     = ''
    'Status'      = ''
    'ProductGuid' = ''
    'Engine'      = [ordered]@{
      'Version'   = ''
      'Signature' = ''
    }
    'ASbaseVDM'   = [ordered]@{
      'Version'   = ''
      'Signature' = ''
    }
    'AVbaseVDM'   = [ordered]@{
      'Version'   = ''
      'Signature' = ''
    }
    'ASdeltaVDM'  = [ordered]@{
      'Version'   = ''
      'Signature' = ''
    }
    'AVdeltaVDM'  = [ordered]@{
      'Version'   = ''
      'Signature' = ''
    }
    'NISengine'   = [ordered]@{
      'Version'   = ''
      'Signature' = ''
    }
    'NISbaseVDM'  = [ordered]@{
      'Version'   = ''
      'Signature' = ''
    }
    'NISfullVDM'  = [ordered]@{
      'Version'   = ''
      'Signature' = ''
    }
    'Platform'    = [ordered]@{
      'Version'   = ''
      'Signature' = ''
    }
  }
  return $record
}

function New-Record() {
  $record = [ordered]@{
    'StartTime'          = ''
    'Process'            = ''
    'EndTime'            = ''
    'ProductSearch'      = (New-ProductSearchRecord)
    'AccumulatePackages' = (New-AccumulatePackagesRecord)
    'PackageDiscovery'   = (New-PackagesDiscoveryRecord)
    'PatchApplication'   = (New-PatchApplicationRecord)
    'Update'             = (New-UpdateRecord)
    'ValidateUpdate'     = (New-ValidateUpdateRecord)
  }
  return $record
}

function New-UpdateRecord() {
  $record = [ordered]@{
    'ProductName'       = ''
    'PackageIdentifier' = '' # guid
    'Directory'         = ''
    'Files'             = @(
      [ordered]@{
        'FileName'  = ''
        'Signature' = ''
        'Version'   = ''
      }
    )
    'SignatureLocation' = [ordered]@{
      'From' = ''
      'To'   = ''
    }
    'SignatureSource'   = ''
  }
  return $record
}

function New-ValidateUpdateRecord() {
  $record = [ordered]@{
    'Update'             = ''
    'Updates'            = @(
      [ordered]@{
        'ASDeltaVDM' = [ordered]@{
          'Original'  = ''
          'UpdatedTo' = ''
        }
      }
      [ordered]@{
        'AVDeltaVDM' = [ordered]@{
          'Original'  = ''
          'UpdatedTo' = ''
        }
      }
    )
    'DeltaUpdateFailure' = ''
    'BddUpdateFailure'   = ''  
  }
  return $record
}

function Read-AccumulatePackages([collections.arrayList]$record, [int]$index) {
  Write-Verbose "Read-AccumulatePackages([collections.arrayList]$($record.Count), [int]$index)"
  $cleanRecord = Read-RecordProperty -record $record -index $index
  $accumulateRecord = New-AccumulatePackagesRecord
  $accumulateRecord.PackageName = Read-PropertyValue -record $cleanRecord -propertyName 'PackageName' -propertyNamePrefix $startOfLinePattern
  return $accumulateRecord
}

function Read-ComponentInfo([collections.arrayList]$record) {
  return Format-ComponentResults -files $record -pattern '[\w\s]+' -formatName
}

function Read-FileInfo([collections.arrayList]$record) {
  return Format-ComponentResults -files $record -pattern '\w+\.\w+'
}

function Read-PackageDiscovery([collections.arrayList]$record, [int]$index) {
  Write-Verbose "Read-PackageDiscovery([collections.arrayList]$($record.Count), [int]$index)"
  $cleanRecord = Read-RecordProperty -record $record -index $index
  $discoveryRecord = New-PackagesDiscoveryRecord
  $discoveryRecord.Directory = Read-PropertyValue -record $cleanRecord -propertyName 'Directory'
  
  $packageIdentifier = Read-PropertyName -record $cleanRecord -propertyName $guidPattern
  $discoveryRecord.PackageIdentifier = $packageIdentifier #Read-PropertyValue -record $cleanRecord -propertyName $packageIdentifier
  
  #test
  $components = Read-ComponentInfo -record $cleanRecord
  $discoveryRecord = Add-ComponentsToResult -components $components -resultRecord $discoveryRecord
  Write-Host "Components: $($components | out-string)" -ForegroundColor Green
  Write-Host "Discovery Record: $($discoveryRecord | out-string)" -ForegroundColor Green
  #end test

  # $discoveryRecord.Engine = Read-PropertyValue -record $cleanRecord -propertyName 'Engine'
  # $discoveryRecord.ASBaseVDM = Read-PropertyValue -record $cleanRecord -propertyName 'AS Base VDM'
  # $discoveryRecord.AVBaseVDM = Read-PropertyValue -record $cleanRecord -propertyName 'AV Base VDM'
  # $discoveryRecord.ASDeltaVDM = Read-PropertyValue -record $cleanRecord -propertyName 'AS Delta VDM'
  # $discoveryRecord.AVDeltaVDM = Read-PropertyValue -record $cleanRecord -propertyName 'AV Delta VDM'

  return $discoveryRecord
}

function Read-PatchApplication([collections.arrayList]$record, [int]$index) {
  Write-Verbose "Read-PatchApplication([collections.arrayList]$($record.Count), [int]$index)"
  $cleanRecord = Read-RecordProperty -record $record -index $index
  $patchRecord = New-PatchApplicationRecord
  $patchRecord.Files = [collections.arrayList]::new()
  $filePattern = '^Patched\s+(?<fileName>.+?)\s+?to\s+(?<Version>[\d\.]+)'
  foreach ($line in $cleanRecord) {
    $regexMatch = Find-Match -line $line -pattern $filePattern
    if ($regexMatch) {
      [void]$patchRecord.Files.Add([ordered]@{
          'FileName' = $regexMatch['fileName']
          'Version'  = $regexMatch['Version']
        })
    }
  }

  $patchRecord.Files = $patchRecord.Files.ToArray()
  return $patchRecord
}

function Read-ProductSearch([collections.arrayList]$record, [int]$index) {
  Write-Verbose "Read-ProductSearch([collections.arrayList]$($record.Count), [int]$index)"
  $cleanRecord = Read-RecordProperty -record $record -index $index
  $searchRecord = New-ProductSearchRecord

  # populate search record root properties
  $searchRecord.Product = Read-PropertyName -record $cleanRecord -propertyName '(Microsoft.+?)'
  $searchRecord.Status = Read-PropertyValue -record $cleanRecord -propertyName 'Status'
  $searchRecord.ProductGuid = Read-PropertyValue -record $cleanRecord -propertyName 'ProductGUID'

  # populate search record components
  $components = Read-ComponentInfo -record $cleanRecord
  $searchRecord = Add-ComponentsToResult -components $components -resultRecord $searchRecord
  return $searchRecord
}

function Read-PropertyName([collections.arrayList]$record, [string]$propertyName, [string]$propertyNamePrefix = '.+?', [string]$separator = ':') {
  return (Read-PropertyNameValue -record $record -propertyName $propertyName -propertyNamePrefix $propertyNamePrefix -separator $separator).PropertyName
}

function Read-PropertyNames([collections.arrayList]$record, [string]$propertyName, [string]$propertyNamePrefix = '.+?', [string]$separator = ':') {
  return (Read-PropertyNameValue -record $record -propertyName $propertyName -propertyNamePrefix $propertyNamePrefix -separator $separator -all).PropertyName
}

function Read-PropertyNameValue(
  [collections.arrayList]$record, 
  [string]$propertyName, 
  [string]$propertyNamePrefix = '.+?', 
  [string]$separator = ':',
  [switch]$all
) {
  $pattern = "$($propertyNamePrefix)(?<propertyName>$($propertyName))\s*?$separator\s*?(?<propertyValue>.*)"
  Write-Verbose "Read-PropertyNameValue([collections.arrayList]$($record.Count), [string]$propertyName, [string]$propertyNamePrefix, [string]$separator)"
  $kvpCollection = [collections.arrayList]::new()
  
  foreach ($line in $record) {
    $regexMatch = Find-Match -line $line -pattern $pattern
    if ($regexMatch) {
      $propertyValue = $regexMatch['propertyValue'].Trim()
      $propertyName = $regexMatch['propertyName']
      Write-Verbose "Property name value found: $propertyName = $propertyValue"
      $kvp = @{
        'PropertyName'  = $propertyName
        'PropertyValue' = $propertyValue
      }
      if ($all) {
        [void]$kvpCollection.Add($kvp)
      }
      else {
        return $kvp
      }
    }
  }

  if ($all) {
    return $kvpCollection
  }
  Write-Warning "Property name value not found: $propertyName"
  return $null
}

function Read-PropertyNameValues([collections.arrayList]$record, [string]$propertyName, [string]$propertyNamePrefix = '.+?', [string]$separator = ':') {
  return Read-PropertyNameValue -record $record -propertyName $propertyName -propertyNamePrefix $propertyNamePrefix -separator $separator -all
}

function Read-PropertyValue([collections.arrayList]$record, [string]$propertyName, [string]$propertyNamePrefix = '.+?', [string]$separator = ':') {
  return (Read-PropertyNameValue -record $record -propertyName $propertyName -propertyNamePrefix $propertyNamePrefix -separator $separator).PropertyValue
}

function Read-PropertyValues([collections.arrayList]$record, [string]$propertyName, [string]$propertyNamePrefix = '.+?', [string]$separator = ':') {
  return (Read-PropertyNameValue -record $record -propertyName $propertyName -propertyNamePrefix $propertyNamePrefix -separator $separator -all).PropertyValue
}

function Read-Record([collections.arrayList]$record, [int]$index) {
  Write-Verbose "Read-Record([collections.arrayList]$($record.Count), [int]$index)"
  $newRecord = Read-RecordMetaData -record $record -newRecord (New-Record)

  for ($recordIndex = 0; $recordIndex -lt $record.Count; ) {
    $line = $record[$recordIndex]
    $recordIndex++
    if (!$line) {
      continue
    }

    $regexMatch = Find-Match -line $line -pattern $recordPropertyPattern
    if ($regexMatch) {
      $recordPropertyName = $regexMatch['propertyName']
      switch ($recordPropertyName) {
        'ProductSearch' {
          $newRecord.ProductSearch = Read-ProductSearch $record $recordIndex
        }
        'AccumulatePackages' {
          $newRecord.AccumulatePackages = Read-AccumulatePackages $record $recordIndex
        }
        'PackageDiscovery' {
          $newRecord.PackageDiscovery = Read-PackageDiscovery $record $recordIndex
        }
        'PatchApplication' {
          $newRecord.PatchApplication = Read-PatchApplication $record $recordIndex
        }
        'Update' {
          $newRecord.Update = Read-Update $record $recordIndex
        }
        'ValidateUpdate' {
          $newRecord.ValidateUpdate = Read-ValidateUpdate $record $recordIndex
        }
        default {
          Write-Error "Unknown record type: $recordPropertyName index: $index recordIndex: $recordIndex"
        }
      }
    }
  }

  Write-Host "returning record $($records.Count): $($newRecord | out-string)" -ForegroundColor Green
  return $newRecord
}

function Read-RecordMetaData([collections.arrayList]$record, [collections.specialized.orderedDictionary]$newRecord) {
  Write-Verbose "Read-RecordMetaData([collections.arrayList]$($record.Count), [collections.specialized.orderedDictionary]$newRecord)"
  # set meta data
  $newRecord.StartTime = Read-PropertyValue -record $record -propertyName 'Start Time' -propertyNamePrefix $startOfLinePattern
  $newRecord.Process = Read-PropertyValue -record $record -propertyName 'Process' -propertyNamePrefix $startOfLinePattern
  $newRecord.Command = Read-PropertyValue -record $record -propertyName 'Command' -propertyNamePrefix $startOfLinePattern
  $newRecord.Administrator = Read-PropertyValue -record $record -propertyName 'Administrator' -propertyNamePrefix $startOfLinePattern
  $newRecord.Version = Read-PropertyValue -record $record -propertyName 'Version' -propertyNamePrefix $startOfLinePattern
  $newRecord.EndTime = Read-PropertyValue -record $record -propertyName 'End Time' -propertyNamePrefix $startOfLinePattern
  return $newRecord
}

function Read-RecordProperty([collections.arrayList]$record, [int]$index) {
  # trim $record starting from $index
  $cleanRecord = [collections.arrayList]::new()
  [void]$cleanRecord.AddRange(@($record.GetRange($index, $record.Count - $index)))
  $lastIndex = $cleanRecord.Count - 1
  $foundTerminator = $false
  # find next record property
  for ($i = 0; $i -lt $cleanRecord.Count; $i++) {
    $line = $cleanRecord[$i]
    $isMatch = [regex]::IsMatch($line, $recordPropertyPattern)
    if ($isMatch) {
      $foundTerminator = $true
      $lastIndex = $i
      break
    }
    elseif ($i -ge $lastIndex) {
      # -and [regex]::IsMatch($line, $recordSeparator)) {
      $foundTerminator = $true
      $lastIndex = $i
    }
  }

  #trim $record ending at $lastIndex
  [void]$cleanRecord.RemoveRange($lastIndex, $cleanRecord.Count - $lastIndex)
  
  if ($cleanRecord -and $foundTerminator) {
    Write-Verbose "Record property found: $($cleanRecord | out-string)"
    # remove pipe characters with ,
    return , $cleanRecord
  }
  
  Write-Error "unable to determine record property: $($record | out-string)"
  return $null
}

function Read-Records($logFilePath) {
  $streamReader = [System.IO.StreamReader]::new($logFilePath)
  $inRecord = $false
  $index = 0
  $record = [collections.arrayList]::new()
  #$records = [collections.arrayList]::new()

  while ($streamReader.EndOfStream -eq $false) {
    $line = $streamReader.ReadLine()
    $index++

    if ($line.Length -eq 0) {
      continue
    }
    elseif ([regex]::IsMatch($line, $recordSeparator) -and !$inRecord) {
      # start new record
      $inRecord = $true
      #$global:mpSigStubLogResult = Read-Record $streamReader $index $inRecord
      #continue
    }
    elseif ([regex]::IsMatch($line, $recordSeparator) -and $inRecord) {
      $inRecord = $false
      # add record to results
      if ($record.Count -gt 0) {
        [void]$records.Add((Read-Record $record $index))
        $record = [collections.arrayList]::new()
      }
      else {
        Write-Error "No record found index: $index"
        #return 1  
      }        
      continue
    }
    elseif ($inRecord) {
      [void]$record.Add($line)
    }
    elseif (!$inRecord) {
      Write-Error "Unknown Record log file format index: $index"
      #return 1
    }
  }
  return $records
}

function Read-Update([collections.arrayList]$record, [int]$index) {
  Write-Verbose "Read-Update([collections.arrayList]$($record.Count), [int]$index)"
  $cleanRecord = Read-RecordProperty -record $record -index $index
  $updateRecord = New-UpdateRecord
  $updateRecord.ProductName = Read-PropertyValue -record $cleanRecord -propertyName 'Product name' #-propertyNamePrefix $startOfLinePattern
  $updateRecord.PackageIdentifier = Read-PropertyName -record $cleanRecord -propertyName $guidPattern
  $updateRecord.Directory = Read-PropertyValue -record $cleanRecord -propertyName 'Directory'
  $signatureLocation = Read-PropertyValue -record $cleanRecord -propertyName 'SignatureLocation' -propertyNamePrefix $startOfLinePattern -separator 'changed'

  if ($signatureLocation) {
    $pattern = 'from\s+(?<from>.+?)\s+to\s+(?<to>.+)'
    $regexMatch = Find-Match -line $signatureLocation -pattern $pattern
    $updateRecord.SignatureLocation.From = $regexMatch['from']
    $updateRecord.SignatureLocation.To = $regexMatch['to']
    $updateRecord.SignatureSource = Read-PropertyValue -record $cleanRecord -propertyName 'Signatures updated from' -propertyNamePrefix $startOfLinePattern -separator ' '

  }
  else {
    Write-Warning "SignatureLocation not found: $signatureLocation"
  }
  

  $updateRecord.Files = Read-FileInfo -record $cleanRecord
  return $updateRecord
}

function Read-ValidateUpdate([collections.arrayList]$record, [int]$index) {
  Write-Verbose "Read-ValidateUpdate([collections.arrayList]$($record.Count), [int]$index)"
  $cleanRecord = Read-RecordProperty -record $record -index $index
  $validateRecord = New-ValidateUpdateRecord
  $versionPattern = '(?<original>.+?)\s+?(?<updatedTo>.+)'

  $validateRecord.DeltaUpdateFailure = Read-PropertyValue -record $cleanRecord -propertyName 'DeltaUpdateFailure' -propertyNamePrefix $startOfLinePattern -separator 'set to'
  $validateRecord.BddUpdateFailure = Read-PropertyValue -record $cleanRecord -propertyName 'BDDUpdateFailure' -propertyNamePrefix $startOfLinePattern -separator 'set to'

  $asDeltaVDM = Read-PropertyValue -record $cleanRecord -propertyName 'AS delta VDM'
  if ($asDeltaVDM) {
    $asDeltaVersions = Find-Match -line $asDeltaVDM -pattern $versionPattern
    $validateRecord.Updates.ASDeltaVDM.Original = $asDeltaVersions['original']
    $validateRecord.Updates.ASDeltaVDM.UpdatedTo = $asDeltaVersions['updatedTo']
  }

  $avDeltaVDM = Read-PropertyValue -record $cleanRecord -propertyName 'AV delta VDM'
  if ($avDeltaVDM) {
    $avDeltaVersions = Find-Match -line $avDeltaVDM -pattern $versionPattern
    $validateRecord.Updates.AVDeltaVDM.Original = $avDeltaVersions['original']
    $validateRecord.Updates.AVDeltaVDM.UpdatedTo = $avDeltaVersions['updatedTo']
  }

  return $validateRecord
}


main