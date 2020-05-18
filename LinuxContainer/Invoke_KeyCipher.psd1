#
# Module manifest for module 'Invoke_KeyCipher'
#
# Generated by: ERIC
#
# Generated on: 4/21/2020
#

@{

  # Script module or binary module file associated with this manifest.
  RootModule = 'Invoke_KeyCipher.psm1'
  
  # Version number of this module.
  ModuleVersion = '0.1.3'
  
  # Supported PSEditions
  # CompatiblePSEditions = @()
  
  # ID used to uniquely identify this module
  GUID = 'df838163-1064-4c67-89bc-591aa692b570'
  
  # Author of this module
  Author = 'ERIC MUTUA'
  
  # Company or vendor of this module
  CompanyName = 'Techcloud ltd'
  
  # Copyright statement for this module
  Copyright = '(c) ERIC MUTUA. All rights reserved.'
  
  # Description of the functionality provided by this module
  Description = 'Handy tool to encrypt and decrypt files on the fly as well as perform password hashing'
  
  # Minimum version of the PowerShell engine required by this module
  # PowerShellVersion = ''
  
  # Name of the PowerShell host required by this module
  # PowerShellHostName = ''
  
  # Minimum version of the PowerShell host required by this module
  # PowerShellHostVersion = ''
  
  # Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
  # DotNetFrameworkVersion = ''
  
  # Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
  # ClrVersion = ''
  
  # Processor architecture (None, X86, Amd64) required by this module
  # ProcessorArchitecture = ''
  
  # Modules that must be imported into the global environment prior to importing this module
  # RequiredModules = @()
  
  # Assemblies that must be loaded prior to importing this module
  # RequiredAssemblies = @()
  
  # Script files (.ps1) that are run in the caller's environment prior to importing this module.
  # ScriptsToProcess = @()
  
  # Type files (.ps1xml) to be loaded when importing this module
  # TypesToProcess = @()
  
  # Format files (.ps1xml) to be loaded when importing this module
  # FormatsToProcess = @()
  
  # Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
  # NestedModules = @()
  
  # Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
  FunctionsToExport = @("Invoke-KeyCipher")
  
  # Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
  CmdletsToExport = @()
  
  # Variables to export from this module
  VariablesToExport = '*'
  
  # Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
  # AliasesToExport = @()
  
  # DSC resources to export from this module
  # DscResourcesToExport = @()
  
  # List of all modules packaged with this module
  # ModuleList = @()
  
  # List of all files packaged with this module
  FileList = @("KeyCipher_stream_encrypter.py", "base64.exe", "Invoke_KeyCipher.psm1")
  
  # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
  PrivateData = @{
  
      PSData = @{
  
          # Tags applied to this module. These help with module discovery in online galleries.
            Tags = @("powershell", "python", "base64", "Certutil", "Encrypt", "Decrypt", "Cipher", "Crypto", "Decode", "FileEncryption", "PasswordHashing", "KeyCipher")
  
          # A URL to the license for this module.
          # LicenseUri = ''
  
          # A URL to the main website for this project.
            ProjectUri = 'https://github.com/ertush/KeyCipher_Crypto_Py.git'
  
          # A URL to an icon representing this module.
          # IconUri = ''
  
          # ReleaseNotes of this module
          # ReleaseNotes = ''
  
          # Prerelease string of this module
          # Prerelease = ''
  
          # Flag to indicate whether the module requires explicit user acceptance for install/update/save
          # RequireLicenseAcceptance = $false
  
          # External dependent modules of this module
          # ExternalModuleDependencies = @()
  
      } # End of PSData hashtable
  
  } # End of PrivateData hashtable
  
  # HelpInfo URI of this module
    HelpInfoURI = 'https://github.com/ertush/KeyCipher_Crypto_Py.git'
  
  # Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
  # DefaultCommandPrefix = ''
  
  }