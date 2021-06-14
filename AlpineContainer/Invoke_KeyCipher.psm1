function Invoke-KeyCipher(){
<#
.SYNOPSIS
	docker run --rm -it -v <input-bind> -v <output-bind> -v <log-bind> invoke-keycipher:<tag> encrypt/decrypt/hash <secret_passphrase> ./etc/input/<file_name>
.DESCRIPTION
	Encrypt / Decrypt files

.FUNCTIONALITY
	Invoke KeyCipher enciphering / deciphering python script

.EXAMPLE
	File Encryption/Decryption Examples

	# Encryptin flowers.jpg

	$ input-bind=~/.invoke-keycipher:/module/etc/input
	$ output-bind=~/.invoke-keycipher:/module/etc/output
	$ log-bind=~/.invoke-keycipher/var/log:/tmp/KeyCipher
	$ docker run --rm -it -v $input-bind -v $output-bind -v $log-bind invoke-keycipher:v0.1.3 encrypt dexT@pa55 ./etc/input/flowers.jpg
	
	# Decrypting flowers.jpg

	> $env:input=C:\\Users\\Doe\\Pictures\\:/module/etc/input
	> $env:output=C:\\Users\\Doe\\Pictures\\:/module/etc/output
	> $env:log=C:\\Users\\Doe\\Documents\\Logs:/tmp/KeyCipher
	> docker run --rm -it -v $env:input -v $env:output -v $env:log invoke-keycipher:v0.1.3 decrypt dexT@pa55 ./etc/input/flowers.jpg

	# Hashing John Doe's Email Address with secret key
	> docker run --rm -it invoke-keycipher:v0.1.3 hash my5ecReT_p@55 john.doe@hotmail.com

	# Unhashing John Doe's Email Address
	> docker run --rm -it invoke-keycipher:v0.1.3 unhash my5ecReT_p@55 '3817BX8YJ18%6U25BW86' 

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

		[parameter(position = 2, mandatory = $false)]
		[String] $key = '-',

		[parameter(position = 3, 
				   mandatory = $false, 
				   ValueFromPipelineByPropertyName = $true
		)]
		[Alias('FullName')]
		[String] $inFilePath ,

		[parameter(
			position = 4, 
			mandatory = $false, 
			ValueFromPipelineByPropertyName = $true
		)]
		
		[Alias('DirectoryName')]
		[String] 
		$outFilePath = $(
						#[string]$(Join-Path /tmp $($(@($inFilePath.split('/'))[@($inFilePath.split('/')).count - 1])).split('.')[0])
						$("./etc/output");
						),

		[parameter(position = 5, mandatory = $false)]
		[int] $lineBufferSize = 10,

		[parameter(position = 6, mandatory = $false)]
		[switch] $fullEncryption = $false,
		[switch] $retainAllFiles = $false
	)

	begin 
	{
		
		$ErrorActionPreference = "Silently Continue"

		# Setting OutFilePath param
		$defaultOutPath = $([string]$(Join-Path /tmp $($(@($inFilePath.split('/'))[@($inFilePath.split('/')).count - 1])).split('.')[0]));
							 
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
		

		$inputFileName = $(@($inFilePath.split('/'))[@($inFilePath.split('/')).count - 1])
		$isInputFileNameWithDots = $($($inputFileName.Split('.').Length) -gt 2)
		$isInputFileNameWithSpaces = $($($inputFileName.Split(' ').Length) -ge 2)
		$inFileExt = $($inputFileName.split('.')[$inputFileName.Split('.').Length -1])

		# Check if mode is a Path

		$isModeAPath = $(
			$mode -eq $("hash") ||
			$mode -eq $("unhash") ||
			$mode -eq $("help") ||
			$mode -eq $("examples")
			);

		# Sanitize InputFileName
		if($isInputFileNameWithDots){
			if(-not $isModeAPath){
				$inputFileName_ = $inputFileName.Replace('.', '_');
				$inputFileName_.Split('_')[$inputFileName_.Split('_').Length - 1];
				$inputFileNameSanitized = $inputFileName_.Replace($inputFileName_.Split('_')[$inputFileName_.Split('_').Length - 1], $('.'+$inFileExt));
		
				# Rename file to sanitized filename
				
				
				Move-Item $inFilePath $($inFilePath.Replace($inputFileName, $inputFileNameSanitized));
				if(Test-Path $inFilePath){ Remove-Item $inFilePath }
					$inputFileName = $inputFileNameSanitized;
				}
			
		}
	
		if($isInputFileNameWithSpaces){
			if(-not $isModeAPath){
				$inputFileNameSnt = $inputFileName.Replace(' ','~');

			# Rename file to sanitized filename
			Move-Item $inFilePath $($inFilePath.Replace($inputFileName, $inputFileNameSnt));
			if(Test-Path $inFilePath){ Remove-Item $inFilePath }
			$inputFileName = $inputFileNameSnt;
			}
		}

		foreach($char in @('(',')','[',']','$','"','&')){
			if(-not $isModeAPath){
				if($inputFileName.Contains($char)){
					$inputFileNameSntzd = $inputFileName.Replace($char, '-');
					# Rename file to sanitized filename
					Move-Item $inFilePath $($inFilePath.Replace($inputFileName, $inputFileNameSntzd));
					if(Test-Path $inFilePath){ Remove-Item $inFilePath }
					$inputFileName = $inputFileNameSntzd;
				}
			}
		}


		# Temporary Directory
		if($outFilePath -ne '-'){
			if(-not $(Test-Path /tmp/$($inputFileName.split('.')[0]))){
				mkdir /tmp/$($inputFileName.split('.')[0]) | Out-Null
			}
		}
		 
		# Instantiating other constants
		$base64EncodeFilePath = $(Join-path /tmp/$($inputFileName.split('.')[0]) "Encoded.bs64enc") 
		$bsDecodeName = $inputFileName.replace($inFileExt, $($("dec64.")+$inFileExt))
		$base64DecodeFilePath = $(Join-path $outFilePath $bsDecodeName)
		$pt_ext = $('enc-')+$([string]$lineBufferSize)
		$possibleEncipherPath = $(Join-path /tmp/$($inputFileName.split('.')[0]) $inputFileName.replace($inFileExt, $($($pt_ext+'.')+$inFileExt)))
		
		if(Test-Path $possibleEncipherPath){
			$encipherFilePath = $(Join-path /tmp/$($inputFileName.split('.')[0]) $inputFileName.replace($inFileExt, $($($pt_ext+'.')+$inFileExt)))
			
		}
		else 
		{
			$encipherFilePath = $(Join-path /tmp/$($inputFileName.split('.')[0]) $inputFileName.replace($inFileExt, $('enc.')+$inFileExt)) 
			
		}
		
		$decipherFilePath = $(Join-path /tmp/$($inputFileName.split('.')[0]) "Deciphered.dec") 	
		$isPython = $($(which python | Select-String 'python').Matches.Success)
		$LogPath = ""
		$isEncipherFilePartial = $($encipherFilePath.Split('enc')[1] -eq $($pt_ext.Split('enc')[1]+'.'+$inFileExt))

		# Setting the module installation path
		if(Test-Path $("/module/Invoke_KeyCipher.psm1")){
			$moduleInstallationPath = $('.')
		}

		# Setting and testing the base64util path
		$isBase64Util = $(Test-Path $(Join-Path $moduleInstallationPath 'base64util'))
		Set-Alias base64util $(Join-Path $moduleInstallationPath 'base64util')
	}

	process
	{
		# Checking whether the Log File exist
		if( -not $(Test-Path $(Join-path /tmp/ "KeyCipher"))){
			mkdir  $(Join-path /tmp/ "KeyCipher") | Out-Null
		}

		# Instantiate Log file
		$LogPath = $(Join-path /tmp/ "KeyCipher/KeyCipher.log")

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
					if($inFilePath.Contains('/') -or $inFilePath.Contains('/')){
						Write-Host "[!] Warning: The string you are trying to encrypt could be a path" -ForegroundColor Yellow 
					}
	
					$passHash = $(python $keyCipherStream --encrypt $key $inFilePath -m)
					Set-Content -Path $(Join-Path /tmp/ passHash) -Value $passHash
							
					return "[Hash] "+$passHash+"`n[+] Done" 
				}
			 }
			 $("unhash")
			 {
				#Password unhashing
				Write-Host "[+] Begninnig Password unhashing ..." -ForegroundColor Cyan
	
					$keyCipherStream = $(Join-Path $moduleInstallationPath 'KeyCipher_stream_encrypter.py')
					if($isPython -and $(Test-Path $keyCipherStream)){
						#$unhashedPass = $(Get-Content -Path $(Join-Path /tmp/ passHash))
						if(Test-Path $(Join-Path /tmp/ passHash)){Remove-Item $(Join-Path /tmp/ passHash)}
						return "[Password] "+$(python $keyCipherStream --decrypt $key $inFilePath -m)+"`n[+] Done"
						
					}	
			 }		
			 $("help"){
				# Show Help 
				Get-help Invoke-KeyCipher -Full
			 }
			 $("examples"){
				 # Show Examples
				Get-help Invoke-KeyCipher -Examples
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

		base64util encode $inFilePath $base64EncodeFilePath 
				
	}
	else
	{
		"["+$(Get-Date)+"][base64Encode] :: ERROR :: File Not Found (base64util).`n" >> $LogPath
	}
}

# Decode function

function base64Decode()
{
	

	if($isBase64Util)
	{
		$isdecipherFilePath = $(Test-path $decipherFilePath)
		if($isdecipherFilePath)
		{  
			# Decoded as a line

			base64util decode $decipherFilePath $base64DecodeFilePath | Out-Null
			 
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
					if(Test-Path /tmp/$($inputFileName.split('.')[0])){Remove-Item -Recurse /tmp/$($inputFileName.split('.')[0]) }
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
		"["+$(Get-Date)+"][base64Decode] :: ERROR :: File Not Found (base64util).`n" >> $LogPath

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
			
			if ($fullEncryption -eq $true){
				$isPartialEncryption = $false
			}
			
			if($(Get-Variable -Name lineBufferSize).IsValidValue($lineBufferSize) -and $($lineBufferSize -gt 1)){
				$isPartialEncryption = $true
			}
			
			# Partial File Encryption
			if ($isPartialEncryption -and $($sizeBs64Buffer -ge 0))
			{
				
				if ($lineCountBs64Buffer -eq 1){
					# Encryption is done character by character
					$line = $base64EncBuffer.Substring(0, $lineBufferSize)
					
					# Debug log
					"["+$(Get-Date)+"][encipherFile] :: DEBUG :: ["+$line, $($line | Measure-Object -Character).Characters+"] Attempting partial encryption.`n" >> $LogPath
	
					
					# Encrypt byte after byte
					$enc_line = $(python $(Join-Path $moduleInstallationPath 'KeyCipher_stream_encrypter.py') --encrypt $key $line -m)

					# Append the unecrypted text
					$unencryptedLine = $base64EncBuffer.SubString($lineBufferSize, $($([int]$($charCountBs64Buffer - $lineBufferSize)) - 2))

					# Saving Everything to File 
					$($enc_line+$unencryptedLine) >  $($encipherFilePath.Replace('enc', $pt_ext));
				} 
				
				Write-host "[+] Verifying and Saving Encrypted File..." -ForegroundColor Gray
				if(Test-Path $base64EncodeFilePath){Remove-Item $base64EncodeFilePath}

				if(Test-Path $($encipherFilePath.Replace('enc', $pt_ext))){
					Copy-Item $($encipherFilePath.Replace('enc', $pt_ext)) $outFilePath
					Remove-Item $inFilePath
				}
		
			}
			else 
			{
				# Full file Encryption
		
				if ($lineCountBs64Buffer -eq 1)
				{
					$line = $base64EncBuffer;
					
					# Debug log
					"["+$(Get-Date)+"][encipherFile] :: DEBUG :: ["+$($line | Measure-Object -Character).Characters+"] Attempting Full encryption.`n" >> $LogPath
					
					# Encryption is done byte after byte
					$enc_line = $(python $(Join-Path $moduleInstallationPath 'KeyCipher_stream_encrypter.py') --encrypt $key $line -m)
					
					# Saving Everything to File
					$enc_line > $encipherFilePath
					
				}

				Write-host "[+] Verifying and Saving Encrypted File..." -ForegroundColor Gray
			
				if(Test-Path $encipherFilePath){
					Copy-Item $encipherFilePath $outFilePath
					Remove-Item $inFilePath
				}
			}
		}
		else
		{	
			# Error log
			"["+$(Get-Date)+"][encipherFile] :: ERROR :: keymode not set or Python not found.`n" >> $LogPath
		}

	}
	else
	{
		# Error log
		"["+$(Get-Date)+"][encipherFile] :: ERROR :: File Not Found ("+ $base64EncodeFilePath +").`n" >> $LogPath
	}
}

function decipherFile(){
	# Sanitize Input File Name for Decryption

	if (Test-Path $(Join-path "./etc/input" $inputFileName.replace($inFileExt, $('enc.')+$inFileExt))){
		$encipherFilePath = $(Join-path "./etc/input" $inputFileName.replace($inFileExt, $('enc.')+$inFileExt));
	}
	else
	{
		$encipherFilePath = $(Join-path "./etc/input" $inputFileName.replace($inFileExt, $($($pt_ext+'.')+$inFileExt)));
	}

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

				# Debug Log
				"["+$(Get-Date)+"][decipherFile] :: DEBUG :: Attempting File Partial Decryption.`n" >> $LogPath
		
				$line = $encipherFileBuffer.SubString(0, $lineBufferSize); 
				
				$dec_line = $(python $(Join-Path $moduleInstallationPath 'KeyCipher_stream_encrypter.py') --decrypt $key $line -m)  
				
				$unecryptedLine = $encipherFileBuffer.SubString($lineBufferSize, $($([int]$($charCountEncipherBuffer - $lineBufferSize)) -2 )) 

				# Saving Everything to File
				$($dec_line+$unecryptedLine) > $decipherFilePath
				
				# Clean up
				Write-host "[+] Removing temporary files..." -ForegroundColor Gray
				if(Test-Path $base64DecodeFilePath){Remove-Item $base64DecodeFilePath}
			}
			else
			{
			# For Full file decryption
		
			# Debug Log
			"["+$(Get-Date)+"][decipherFile] :: DEBUG :: Attempting File Partial Decryption.`n" >> $LogPath
	
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
			# Error log                      
			"["+$(Get-Date)+"][decipherFile] :: ERROR :: keymode not set or Python not found.`n" >> $LogPath
		}
	}
	else
	{  
		# Error log
		"["+$(Get-Date)+"][decipherFile]:: ERROR :: File Not Found ("+ $encipherFilePath +").`n" >> $LogPath
	}

}
