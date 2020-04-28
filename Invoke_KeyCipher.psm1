function Invoke-KeyCipher(){
<#
.SYNOPSIS
	Invoke-KeyCipher [mode (encrypt | derypt)] [key secret] [inFilePath | string_stream] [outFilePath path_to_save]

.DESCRIPTION
	Encrypt / Decrypt files

.FUNCTIONALITY
	Invoke KeyCipher enciphering / deciphering python script

.EXAMPLE
	File Encryption/Decryption Examples

	Invoke-KeyCipher decrypt pa55w0rd .\input\File.ext .\out\File.ext 

	PS > Invoke-KeyCipher encrypt pa55w0rd .\input\File.ext

	PS > Invoke-KeyCipher encrypt my_Secret_key 5ecret@pa55w0rd
	
	PS > Invoke-KeyCipher -mode encrypt -key ricoTush /my/file/in/directory -lineBufferSize 80 # This saves to default path which is %HOMEDRIVE%\USERS\PUBLIC\DOCUMENTS 

	Password Hashing Examples

	PS > Invoke-KeyCipher hash secret mypassword

	PS > Invoke-KeyCipher unhash secret mypassword

	Encrypting Multiple Files

	PS > $files = $(ls C:\Users\ERIC\Downloads\Video\Strike* | ? {$($_.length / 1mb) -lt 200} | %{ $_.FullName })  
	
	PS > $files | %{Write-Progress -Activity "Encrypting.." -Status $_.Split('\')[$_.Split('\').Length - 1] ; Invoke-KeyCipher encrypt mysecret $_ -lineBufferSize 10 }

	Decrypting Multiple Files

	PS > $files | %{Write-Progress -Activity "Decrypting.." -Status $_.Split('\')[$_.Split('\').Length - 1] ; Invoke-KeyCipher decrypt mysecret $_ -lineBufferSize 10 -retainAllFiles | Out-Null} 

.INPUTS
	[System.String] mode (encrypt | decrypt | hash | unhash)
	[System.String] key (secret)
	[System.String] inputFilePath (location of file *fullpathName)
	[System.String] outFilePath (location of save dir *only directory)
	[Integer] lineBufferSize (for *partial encryption only)
	[Switch] fullEncryption (for *full Encryption)
	[Switch] retainAllFiles (used when *encrypting/decrypting multiple files)

.NOTES

	The Module is only capable of encrypting and decrypting files less than 500 Mb at a reasonable time of approximately 5 - 10 minutes.
	It is advisable to use the -lineBufferSize flag for large files of more than 10 mb and -fullEncryption for files less than 10 mb.
	
	For this version (v 0.1.3) the default encode / decode utility is base64.exe which is more capable compared to certutil.exe which was used in previous versions.

    Author: Eric Mutua
    Date: 22.04.2020
    Version: 0.1.3
#>

	[CmdLetBinding()]
	Param(
		[parameter(position = 1, mandatory = $true)]
		[String] $mode,

		[parameter(position = 2, mandatory = $true)]
		[String] $key,

		[parameter(position = 3, 
				   mandatory = $true, 
				   ValueFromPipelineByPropertyName = $true
		)]
		[Alias('FullName')]
		[String] $inFilePath,

		[parameter(
			position = 4, 
			mandatory = $false, 
			ValueFromPipelineByPropertyName = $true
		)]
		[Alias('DirectoryName')]
		[String] 
		$outFilePath = $(
						[string]$(Join-Path $env:PUBLIC $("\Documents\"+$(@($inFilePath.split('\'))[@($inFilePath.split('\')).count - 1])).split('.')[0])
						),

		[parameter(position = 5, mandatory = $false)]
		[int] $lineBufferSize = 10,

		[parameter(position = 6, mandatory = $false)]
		[switch] $fullEncryption = $false,
		[switch]$retainAllFiles = $false
	)

	begin {

		$ErrorActionPreference = "Silently Continue"

		# Setting OutFilePath param
		$defaultOutPath = $([string]$(Join-Path $env:PUBLIC $("\Documents\"+$(@($inFilePath.split('\'))[@($inFilePath.split('\')).count - 1])).split('.')[0]));
							 
		# Checking mode parameter
		if($($mode -eq "hash") -or $($mode -eq "unhash")){
			$outFilePath = '-'
		}
		else
		{ 
			if($outFilePath -eq $defaultOutPath){
				if(-not $(Test-Path $defaultOutPath)){
					mkdir $defaultOutPath | Out-Null
				}
			}	
				
		}
		

		$inputFileName = $(@($inFilePath.split('\'))[@($inFilePath.split('\')).count - 1])
		$inFileExt = $($inputFileName.split('.')[$inputFileName.Split('.').Length -1])

		# Temporary Directory
		if($outFilePath -ne '-'){
			if(-not $(Test-Path $env:TEMP\$($inputFileName.split('.')[0]))){
				mkdir $env:TEMP\$($inputFileName.split('.')[0]) | Out-Null
			}
		}
		 
		# Instantiating other constants
		$base64EncodeFilePath = $(Join-path $env:TEMP\$($inputFileName.split('.')[0]) "Encoded.bs64enc") 
		$bsDecodeName = $inputFileName.replace($inFileExt, $($("dec64.")+$inFileExt))
		$base64DecodeFilePath = $(Join-path $outFilePath $bsDecodeName)
		$pt_ext = $('enc-')+$([string]$lineBufferSize)
		$possibleEncipherPath = $(Join-path $env:TEMP\$($inputFileName.split('.')[0]) $inputFileName.replace($inFileExt, $($($pt_ext+'.')+$inFileExt)))
		
		if(Test-Path $possibleEncipherPath){
			$encipherFilePath = $(Join-path $env:TEMP\$($inputFileName.split('.')[0]) $inputFileName.replace($inFileExt, $($($pt_ext+'.')+$inFileExt))) 
		}
		else 
		{
			$encipherFilePath = $(Join-path $env:TEMP\$($inputFileName.split('.')[0]) $inputFileName.replace($inFileExt, $('enc.')+$inFileExt)) 
		}
		
		$decipherFilePath = $(Join-path $env:TEMP\$($inputFileName.split('.')[0]) "Deciphered.dec") 	
		$isPython = $($($env:PATH | Select-String 'python27').Matches.Success)
		$LogPath = ""
		$isEncipherFilePartial = $($encipherFilePath.Split('enc')[1] -eq $($pt_ext.Split('enc')[1]+'.'+$inFileExt))
		$version = "0.1.3" 


		# Setting the module installation path
		if(Test-Path $(Join-Path $PSHOME\Modules Invoke_KeyCipher)){
			$moduleInstallationPath = $(Join-Path $PSHOME\Modules Invoke_KeyCipher\)
		}

		if(Test-Path $(Join-Path ${env:ProgramFiles(x86)}\WindowsPowerShell\Modules Invoke_KeyCipher)){
			$moduleInstallationPath = $(Join-Path ${env:ProgramFiles(x86)}\WindowsPowerShell\Modules Invoke_KeyCipher\$version\)
		}
		 
		if(Test-Path $(Join-Path $env:ProgramFiles\WindowsPowerShell\Modules Invoke_KeyCipher)){
			$moduleInstallationPath = $(Join-Path $env:ProgramFiles\WindowsPowerShell\Modules Invoke_KeyCipher\$version\)
		}

		# Setting and testing the base64util path
		$isBase64Util = $(Test-Path $(Join-Path $moduleInstallationPath 'base64.exe'))
		Set-Alias base64 $(Join-Path $moduleInstallationPath 'base64.exe')
	}

	process
	{
		# Checking whether the Log File exist
		if( -not $(Test-Path $(Join-path $env:TEMP "\KeyCipher"))){
			mkdir  $(Join-path $env:TEMP "\KeyCipher") | Out-Null
		}

		# Instantiate Log file
		$LogPath = $(Join-path $env:TEMP "\KeyCipher\KeyCipher.log")

		switch ($mode) {
			$("encrypt")
			{  			
				# Encrypting Files
				Write-Host "[+] Beginning File Encryption ..." -ForegroundColor Green

				base64Encode($isBase64Util, $LogPath) #($isBase64Util, $inFilePath, $LogPath)
				encipherFile($base64EncodeFilePath, $LogPath) #($base64EncodeFilePath, $encipherFilePath, $key, $LogPath, $isPython, $pt_ext)
				
				Write-Host "[+] Done Encrypting" -ForegroundColor Green
				
			}
			$("decrypt")
			 { 
				# Decrypting File
				Write-Host "[+] Beginning File Decryption ..." -ForegroundColor Cyan

				decipherFile($decipherFilePath, $isEncipherFilePartial) #($decipherFilePath, $encipherFilePath, $key, $LogPath, $isPython, $pt_ext, $inFileExt, $isEncipherFilePartial) 
				$decryptionStatus = base64Decode($decipherFilePath, $base64DecodeFilePath) #($decipherFilePath, $base64DecodeFilePath, $LogPath)

				if($($decryptionStatus -ne 'Nul') -or $($decryptionStatus) -ne ''){
					Write-Host $($("[+] ")+$decryptionStatus) -ForegroundColor Cyan
				}
				else
				{
					Write-Host "[+] Done Decrypting" -ForegroundColor Magenta
				}
			 }
			 $("hash")
			 {
				# Password hashing
				Write-Host "[+] Beginning Password hashing ..." -ForegroundColor Green

				$keyCipherStream = $(Join-Path $moduleInstallationPath 'KeyCipher_stream_encrypter.py')

				if($isPython -and $(Test-Path $keyCipherStream)){
					if($inFilePath.Contains('/') -or $inFilePath.Contains('\')){
						Write-Host "[!] Warning: The string you are trying to encrypt could be a path" -ForegroundColor Yellow 
					}
	
					$passHash = $(python $keyCipherStream --encrypt $key $inFilePath -m)
					Set-Content -Path $(Join-Path $env:TEMP passHash) -Value $passHash
							
					return "[Hash] "+$passHash+"`n[+] Done" 
				}
			 }
			 $("unhash")
			 {
				#Password unhashing
				Write-Host "[+] Begninnig Password unhashing ..." -ForegroundColor Cyan
	
					$keyCipherStream = $(Join-Path $moduleInstallationPath 'KeyCipher_stream_encrypter.py')
					if($isPython -and $(Test-Path $keyCipherStream)){
						$unhashedPass = $(Get-Content -Path $(Join-Path $env:TEMP passHash))
						if(Test-Path $(Join-Path $env:TEMP passHash)){Remove-Item $(Join-Path $env:TEMP passHash)}
						return "[Password] "+$(python $keyCipherStream --decrypt $key $unhashedPass -m)+"`n[+] Done"
						
					}	
			 }		
			 
			Default {Write-Host "[!] Please Refer to the help for appropriate mode" -ForegroundColor Yellow}
		}

	}

	end
	{
		
	}
}

# Encode function
function base64Encode(){

	
	if($isBase64Util)
	{	

		base64 encode $inFilePath $base64EncodeFilePath 
				
	}
	else
	{
		"["+$(Get-Date)+"][base64Encode] :: ERROR :: File Not Found (base64.exe).`n" >> $LogPath
	}
}

# Decode function

function base64Decode()
{
	$isdecipherFilePath = $(Test-path $decipherFilePath)

	if($isBase64Util)
	{
		if($isdecipherFilePath)
		{
			# Decoded as a line

			 base64 decode $decipherFilePath $base64DecodeFilePath | Out-Null
			 
			# Checking whether base64 was succesfull

			if($? -ne $true){

				"["+$(Get-Date)+"][base64Decode] :: ERROR :: Incorrect Key attempted decryption.`n" >> $LogPath

				return "Wrong Key! You are not authorised to Decrypt File"
			}
			else{
			   
				Write-host "[+] Verifying & Saving Decrypted file ..." -ForegroundColor Gray
				if(-not $retainAllFiles){
					if(Test-Path $(Join-path $outFilePath $inputFileName.replace($inFileExt, $($($pt_ext+'.')+$inFileExt)))){Remove-Item $(Join-path $outFilePath $inputFileName.replace($inFileExt, $($($pt_ext+'.')+$inFileExt)))}
					if(Test-Path $(Join-path $outFilePath $inputFileName.replace($inFileExt, $('enc.')+$inFileExt))){Remove-Item $(Join-path $outFilePath $inputFileName.replace($inFileExt, $('enc.')+$inFileExt))}
					if(Test-Path $env:TEMP\$($inputFileName.split('.')[0])){Remove-Item -Recurse $env:TEMP\$($inputFileName.split('.')[0]) }
				}
				return "Done"
			}

			
		}
		else
		{
			"["+$(Get-Date)+"][base64Decode] :: ERROR :: File Not Found ("+ $decipherFilePath +").`n" >> $LogPath
			
			return 'Nul'
		}
	}
	else
	{
		"["+$(Get-Date)+"][base64Decode] :: ERROR :: File Not Found (base64.exe).`n" >> $LogPath

	}
}

function encipherFile()
{

	$isBase64EncodeFilePath = $(Test-Path $base64EncodeFilePath) 

	if($isBase64EncodeFilePath){

		if($isPython)
		{	
			Write-host "[+] File Enciphering ..." -ForegroundColor Gray
			
			$base64EncBuffer = $(Get-Content $base64EncodeFilePath)
			$sizeBs64Buffer = $($base64EncBuffer.Length / 1mb)
			$lineCountBs64Buffer = $base64EncBuffer.Count
			$charCountBs64Buffer = $($base64EncBuffer | Measure-Object -Character).Characters
			
			# Checking if input file is fit for full or partial encryption
			
			if ($(Get-Variable -Name fullEncryption).IsValidValue($fullEncryption)){
				$isPartialEncryption = $false
			} 
			if($(Get-Variable -Name lineBufferSize).IsValidValue($lineBufferSize) -and $($lineBufferSize -gt 1)){
				$isPartialEncryption = $true
			}
			
			# Partial File Encryption
			if ($isPartialEncryption -and ($sizeBs64Buffer -gt 1))
			{
				
				if ($lineCountBs64Buffer -eq 1){
					# Encryption is done character by character
					$line = $base64EncBuffer.Substring(0, $lineBufferSize)
					
					# Encrypt byte after byte
					$enc_line = $(python $(Join-Path $moduleInstallationPath 'KeyCipher_stream_encrypter.py') --encrypt $key $line -m)

					# Append the unecrypted text
					$unencryptedLine = $base64EncBuffer.SubString($lineBufferSize, $([int]$($charCountBs64Buffer - $lineBufferSize)))

					# Saving Everything to File 
					$($enc_line+$unencryptedLine) >  $($encipherFilePath.Replace('enc', $pt_ext));
				} 
				
			
				Write-host "[+] Verifying and Saving Encrypted File..." -ForegroundColor Gray
				if(Test-Path $base64EncodeFilePath){Remove-Item $base64EncodeFilePath}
				if(Test-Path $($encipherFilePath.Replace('enc', $pt_ext))){Copy-Item $($encipherFilePath.Replace('enc', $pt_ext)) $outFilePath}
		
			}
			else 
			{
				# Full file Encryption
				
				if ($lineCountBs64Buffer -eq 1)
				{
					$line = $base64EncBuffer;
				
					# Encryption is done byte after byte
					$enc_line = $(python $(Join-Path $moduleInstallationPath 'KeyCipher_stream_encrypter.py') --encrypt $key $line -m)
					
					# Saving Everything to File
					$enc_line > $encipherFilePath
					
				}

				Write-host "[+] Verifying and Saving Encrypted File..." -ForegroundColor Gray
			
				if(Test-Path $encipherFilePath){Copy-Item $encipherFilePath $outFilePath}
			}
		}
		else
		{
			"["+$(Get-Date)+"][encipherFile] :: ERROR :: keymode not set or Python not found.`n" >> $LogPath
		}

	}
	else
	{
		"["+$(Get-Date)+"][encipherFile] :: ERROR :: File Not Found ("+ $base64EncodeFilePath +").`n" >> $LogPath
	}
}

function decipherFile(){

	$isEncipherFilePath = $(Test-Path $encipherFilePath)
		
	if($isEncipherFilePath){

		if($isPython)
		{	
			Write-host "[+] File Deciphering ..." -ForegroundColor Gray
			
			$encipherFileBuffer = $(Get-Content $encipherFilePath)
			$charCountEncipherBuffer = $($encipherFileBuffer | Measure-Object -Character).Characters
			
			if(-not $(Get-Variable -Name isEncipherFilePartial).IsValidValue($isEncipherFilePartial)){
				$isEncipherFilePartial = $($encipherFilePath.Split('enc')[1] -eq $($pt_ext.Split('enc')[1]+'.'+$inFileExt))
			}
			
			# For partial File Decryption
			if($isEncipherFilePartial){

				$line = $encipherFileBuffer.SubString(0, $lineBufferSize); 
				
				$dec_line = $(python $(Join-Path $moduleInstallationPath 'KeyCipher_stream_encrypter.py') --decrypt $key $line -m)  
				
				$unecryptedLine = $encipherFileBuffer.SubString($lineBufferSize, $([int]$($charCountEncipherBuffer - $lineBufferSize))) 

				# Saving Everything to File
				$($dec_line+$unecryptedLine) > $decipherFilePath
				
				# Clean up
				Write-host "[+] Removing temporary files..." -ForegroundColor Gray
				if(Test-Path $base64DecodeFilePath){Remove-Item $base64DecodeFilePath}
			}
			else
			{

			$line = $encipherFileBuffer;
			
			$dec_line = $(python $(Join-Path $moduleInstallationPath 'KeyCipher_stream_encrypter.py') --decrypt $key $line -m) 

			# Saving Everything to File
			$dec_line > $decipherFilePath					   
			
			# Clean up
			Write-host "[+] Removing temporary files..." -ForegroundColor Gray
			if(Test-Path $base64DecodeFilePath){Remove-Item $base64DecodeFilePath}
			}
		}
		else
		{                         
			"["+$(Get-Date)+"][decipherFile] :: ERROR :: keymode not set or Python not found.`n" >> $LogPath
		}
	}
	else
	{
		"["+$(Get-Date)+"][decipherFile]:: ERROR :: File Not Found ("+ $encipherFilePath +").`n" >> $LogPath
	}

}

