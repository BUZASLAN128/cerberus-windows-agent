# Read the shipped constructor default without loading or executing the assembly.
function Get-ReleaseArtifactByteLimit([string]$RuntimeDir) {
  $stream = $null
  $hostPath = Join-Path $RuntimeDir 'Cerberus.Agent.Service.exe'
  if (Test-Path -LiteralPath $hostPath -PathType Leaf) {
    Import-AgentBundleReader
    if ([Cerberus.Agent.Core.AgentSingleFileBundle]::IsBundle($hostPath)) {
      $stream = [IO.MemoryStream]::new([Cerberus.Agent.Core.AgentSingleFileBundle]::ReadAssembly($hostPath, 'Cerberus.Agent.Core.dll'))
    }
  }
  if ($null -eq $stream) { $stream = [IO.File]::OpenRead((Join-Path $RuntimeDir 'Cerberus.Agent.Core.dll')) }
  try {
    $pe = [System.Reflection.PortableExecutable.PEReader]::new($stream)
    try {
      $reader = [System.Reflection.Metadata.PEReaderExtensions]::GetMetadataReader($pe)
      $limits = @(
        foreach ($typeHandle in $reader.TypeDefinitions) {
          $type = $reader.GetTypeDefinition($typeHandle)
          if ($reader.GetString($type.Name) -cne 'AgentUpdateTrust' -or $reader.GetString($type.Namespace) -cne 'Cerberus.Agent.Core') { continue }
          foreach ($methodHandle in $type.GetMethods()) {
            $method = $reader.GetMethodDefinition($methodHandle)
            if ($reader.GetString($method.Name) -cne '.ctor') { continue }
            foreach ($parameterHandle in $method.GetParameters()) {
              $parameter = $reader.GetParameter($parameterHandle)
              if ($reader.GetString($parameter.Name) -cne 'MaxArtifactBytes') { continue }
              $handle = $parameter.GetDefaultValue()
              if ($handle.IsNil) { throw 'Artifact byte limit has no compiled default.' }
              $constant = $reader.GetConstant($handle)
              if ($constant.TypeCode -ne [System.Reflection.Metadata.ConstantTypeCode]::Int64) { throw 'Artifact byte limit must be Int64.' }
              $blob = $reader.GetBlobReader($constant.Value)
              $blob.ReadInt64()
            }
          }
        }
      )
      if ($limits.Count -ne 1 -or $limits[0] -le 0) { throw 'Missing, ambiguous or invalid compiled artifact byte limit.' }
      return [long]$limits[0]
    } finally { $pe.Dispose() }
  } finally { $stream.Dispose() }
}

function Assert-ReleaseArtifactSize([string]$ArtifactPath, [string]$RuntimeDir) {
  $limit = Get-ReleaseArtifactByteLimit $RuntimeDir
  $length = (Get-Item -LiteralPath $ArtifactPath -ErrorAction Stop).Length
  if ($null -eq $length -or $length -le 0 -or $length -gt $limit) {
    throw "Release artifact size $length exceeds the usable range 1..$limit bytes: $ArtifactPath"
  }
}
