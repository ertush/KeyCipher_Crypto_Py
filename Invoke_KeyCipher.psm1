function Invoke-KeyCipher(){
<#
.SYNOPSIS
	Invoke-KeyCipher [mode (encrypt | derypt)] [key secret] [inFilePath | string_stream] [outFilePath path_to_save]   
.DESCRIPTION
	Encrypt / Decrypt files
.FUNCTIONALITY
	Invoke KeyCipher enciphering / deciphering python script
.EXAMPLE
	Invoke-KeyCipher decrypt pa55w0rd .\input\File.ext .\out\File.ext 

	PS > Invoke-KeyCipher encrypt pa55w0rd .\input\File.ext

	PS > Invoke-KeyCipher encrypt my_Secret_key 5ecret@pa55w0rd

	PS > $(ls "C:\Users\ERIC\Desktop\WindowsUpdate.log") | Invoke-KeyCipher -mode encrypt -key ricoTush -lineBufferSize 9

	PS > $(ls "C:\Users\ERIC\Desktop\WindowsUpdate.log") | Invoke-KeyCipher -mode encrypt -key ricoTush -fullEncryption $true
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
							 # The Default Output path
							 $defaultOutPath = [string]$(Join-Path $env:PUBLIC $("\Documents\"+$(@($inFilePath.split('\'))[@($inFilePath.split('\')).count - 1])).split('.')[0]);
							
							 if(-not $(Test-Path $defaultOutPath)){
								mkdir $defaultOutPath
							 }

							 return [System.String]$defaultOutPath
				        ),

		[parameter(position = 5, mandatory = $false)]
		[int] $lineBufferSize = 10,

		[parameter(position = 6, mandatory = $false)]
		[switch] $fullEncription = $false
	)

	begin {

		$ErrorActionPreference = "Silently Continue"
		
		$isCertUtil = $(Test-Path $env:windir\System32\certutil.exe)

		Set-Alias certutil $(Join-path $env:windir "\System32\certutil.exe")

		$inputFileName = $(@($inFilePath.split('\'))[@($inFilePath.split('\')).count - 1])
		$inFileExt = $($inputFileName.split('.')[$inputFileName.Split('.').Length -1])

		# Temporary Directory
		if(-not $(Test-Path $env:TEMP\$($inputFileName.split('.')[0]))){
			mkdir $env:TEMP\$($inputFileName.split('.')[0]) | Out-Null
		}
		 

		$ErrorActionPreference = "SilentlyContinue"
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
		$isPython = $($($env:PATH | Select-String 'python').Matches.Success)
		$LogPath = ""

	}

	process
	{
			# Check if $base64EncodeFilePath is complete to take care of pipeline values
			# For pipeline values only
			# Begin Section for pipelined input parameters
			if(-not $base64EncodeFilePath.Contains($(@($inFilePath.split('\'))[@($inFilePath.split('\')).count - 1]))){
				$ErrorActionPreference = "Silently Continue"
				$isCertUtil = $(Test-Path $env:windir\System32\certutil.exe)
				Set-Alias certutil $(Join-path $env:windir "\System32\certutil.exe")

				$iFileName = $(@($inFilePath.split('\'))[@($inFilePath.split('\')).count - 1])
				
				# Make the temp directory
				if(-not $(Test-Path $env:TEMP\$($iFileName.split('.')[0]))){
					mkdir $env:TEMP\$($iFileName.split('.')[0]) | Out-Null
				}
				
				
				$p_ext = $('enc-')+$([string]$lineBufferSize)
				$iFileExt = $($iFileName.split('.')[$iFileName.Split('.').Length - 1])
				$bsDecodeName = $iFileName.replace($iFileExt, $($("dec64.")+$iFileExt))
				
				# Set paths
				$base64EncodeFilePath = $(Join-path $env:TEMP\$($iFileName.split('.')[0]) "Encoded.bs64enc")
				$psbEncipherPath = $(Join-path $env:TEMP\$($iFileName.split('.')[0]) $iFileName.replace($iFileExt, $($($p_ext+'.')+$iFileExt)))
				
				if(Test-Path $psbEncipherPath){
					$encipherFilePath = $(Join-path $env:TEMP\$($iFileName.split('.')[0]) $iFileName.replace($iFileExt, $($($p_ext+'.')+$iFileExt))) 
				}
				else 
				{
					$encipherFilePath = $(Join-path $env:TEMP\$($iFileName.split('.')[0]) $iFileName.replace($iFileExt, $('enc.')+$iFileExt)) 
				}

				$decipherFilePath = $(Join-path $env:TEMP\$($iFileName.split('.')[0]) "Deciphered.dec")
				$base64DecodeFilePath = $(Join-path $outFilePath $bsDecodeName)
				$isPython = $($($env:PATH | Select-String 'python').Matches.Success)
				$LogPath = ""
				$isEncipherFilePartial = $($encipherFilePath.Split('enc')[1] -eq $($p_ext.Split('enc')[1]+'.'+$iFileExt))
				$inputFileName = $iFileName;
				$pt_ext = $p_ext;
				$inFileExt = $iFileExt;
			}

			# End Begin Section for pipelined values

		if( -not $(Test-Path $(Join-path $env:TEMP "\KeyCipher"))){
			mkdir  $(Join-path $env:TEMP "\KeyCipher") | Out-Null
		}

		# Instantiate Log file
		$LogPath = $(Join-path $env:TEMP "\KeyCipher\KeyCipher.log")

		switch ($mode) {
			$("encrypt")
			{  
				# Encrypting File
				Write-Host "[+] Beginning File Encryption ..." -ForegroundColor Green
				
				#Check whether the stream flag has been set by checking outFilePath
				$is_Stream = $($outFilePath -eq $true)

				if($is_Stream){
					$keyCipherStream = $(Join-Path . '\KeyCipher_stream_encrypter.py')
					if($isPython){
						if($inFilePath.Contains('/') -or $inFilePath.Contains('\')){
							Write-Host "[!] Warning: The string you are trying to encrypt could be a path" -ForegroundColor Yellow 
						}
						return $(python $keyCipherStream --encrypt $_key $inFilePath -m)
					}
				}

				base64Encode($isCertUtil, $inFilePath, $LogPath)
				encipherFile($base64EncodeFilePath, $encipherFilePath, $key, $LogPath, $isPython, $pt_ext)
				
				Write-Host "[+] Done Encrypting" -ForegroundColor Green

			}
			$("decrypt")
			 { 
				# Decrypting File
				Write-Host "[+] Beginning File Decryption ..." -ForegroundColor Cyan

				
				if($_isStream){
					$keyCipherStream = $(Join-Path . '\KeyCipher_stream_encrypter.py')

					if($isPython){
						return $(python $keyCipherStream --encrypt $_key [string]$inFilePath -m)
					}
				}

				decipherFile($decipherFilePath, $encipherFilePath, $key, $LogPath, $isPython, $pt_ext, $inFileExt, $isEncipherFilePartial) 
				$decryptionStatus = base64Decode($decipherFilePath, $base64DecodeFilePath, $LogPath)

				Write-Host $($("[+] ")+$decryptionStatus) -ForegroundColor Magenta
			 }
			Default {Write-Host "[!] Please Refer to the help for appropriate mode" -ForegroundColor Red}
		}

	}

	end
	{
		
	}
}

function base64Encode(){

	
	if($isCertUtil)
	{	

		certutil -encode $inFilePath $base64EncodeFilePath
				
	}
	else
	{
		"["+$(Get-Date)+"][base64Encode] :: ERROR :: File Not Found (certutil.exe).`n" >> $LogPath

		# Alternative for certutil.exe
	    Out-File -InputObject $(python $(Join-Path . '/base64.py') -e $inFilePath) -Path $base64EncodeFilePath
	}
}


function base64Decode()
{
	$isdecipherFilePath = $(Test-path $decipherFilePath)

	if($isCertUtil)
	{
		if($isdecipherFilePath)
		{
			certutil -decode $decipherFilePath $base64DecodeFilePath

			if($? -ne $true){

				"["+$(Get-Date)+"][base64Decode] :: ERROR :: Incorrect Key attempted decryption.`n" >> $LogPath

				return "Wrong Key! You are not authorised to Decrypt File"
			}
			else{
			   
				Write-host "[+] Removing temporary files..." -ForegroundColor Gray

				if(Test-Path $(Join-path $outFilePath $inputFileName.replace($inFileExt, $($($pt_ext+'.')+$inFileExt)))){Remove-Item $(Join-path $outFilePath $inputFileName.replace($inFileExt, $($($pt_ext+'.')+$inFileExt)))}
				if(Test-Path $(Join-path $outFilePath $inputFileName.replace($inFileExt, $('enc.')+$inFileExt))){Remove-Item $(Join-path $outFilePath $inputFileName.replace($inFileExt, $('enc.')+$inFileExt))}
				if(Test-Path $env:TEMP\$($inputFileName.split('.')[0])){Remove-Item -Recurse $env:TEMP\$($inputFileName.split('.')[0]) }
					
				return "Done"
			}

		}
		else
		{
			"["+$(Get-Date)+"][base64Decode] :: ERROR :: File Not Found ("+ $decipherFilePath +").`n" >> $LogPath
			
		}
	}
	else
	{
		"["+$(Get-Date)+"][base64Decode] :: ERROR :: File Not Found (certutil.exe).`n" >> $LogPath

		# Alternative for certutil.exe
		Out-File -InputObject $(python $(Join-Path . '/base64.py') -d $decipherFilePath) -Path $base64DecodeFilePath
			
		if(Test-Path $base64DecodeFilePath){Copy-Item $base64DecodeFilePath $outFilePath}
		if(Test-Path $(Join-path $outFilePath $inputFileName.replace($inFileExt, $($($pt_ext+'.')+$inFileExt)))){Remove-Item $(Join-path $outFilePath $inputFileName.replace($inFileExt, $($($pt_ext+'.')+$inFileExt)))}
		if(Test-Path $(Join-path $outFilePath $inputFileName.replace($inFileExt, $('enc.')+$inFileExt))){Remove-Item $(Join-path $outFilePath $inputFileName.replace($inFileExt, $('enc.')+$inFileExt))}
		if(Test-Path $env:TEMP\$($inputFileName.split('.')[0])){Remove-Item -Recurse $env:TEMP\$($inputFileName.split('.')[0]) }
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
			$sizeBase64Buffer = $base64EncBuffer.Count
			
			# Partial File Encryption
			if ($($sizeBase64Buffer -gt $lineBufferSize) -and $(-not $fullEncription)){

				$innerLineBuffer = $($base64EncBuffer | Select-Object -First $lineBufferSize)
				$_divisor = [int]$innerLineBuffer.Count / 10
				forEach($innerLine in $innerLineBuffer){
					
					$actual_pcnt = [int]$innerLineBuffer.indexOf($innerLine) / $_divisor
					
					# Show Progress
					Show-ProgressBar($actual_pcnt, "Encrypting ")
			
					$enc_line = $(python $(Join-Path . '\KeyCipher_stream_encrypter.py') --encrypt $key $innerLine -m)

					Out-File -FilePath $($encipherFilePath.Replace('enc', $pt_ext)) -Append  -InputObject $enc_line -Encoding string
				} 
				
				# Append the unecrypted text
				$unencryptedLines = $($base64EncBuffer | Select-Object -Last $($sizeBase64Buffer - $lineBufferSize))
				
				Out-File -FilePath $($encipherFilePath.Replace('enc', $pt_ext)) -Append  -InputObject $unencryptedLines -Encoding string
				
				Write-host "[+] Verifying and Saving Encrypted File..." -ForegroundColor Gray
				if(Test-Path $base64EncodeFilePath){Remove-Item $base64EncodeFilePath}
				if(Test-Path $($encipherFilePath.Replace('enc', $pt_ext))){Copy-Item $($encipherFilePath.Replace('enc', $pt_ext)) $outFilePath}
				if(Test-Path $encipherFilePath){Copy-Item $encipherFilePath $outFilePath}
			}
			else 
			{
				# Full file Encryption
				$divisor = [int]$sizeBase64Buffer / 10

				forEach($line in $base64EncBuffer)
				{
					
					$actual_pcnt = [int]$base64EncBuffer.indexOf($line) / $divisor

					# Show Progress
					Show-ProgressBar($actual_pcnt, "Encrypting ")
												
					# Encryption is done line by line
					$enc_line = $(python $(Join-Path . '\KeyCipher_stream_encrypter.py') --encrypt $key $line -m)

					Out-File -FilePath $encipherFilePath -Append  -InputObject $enc_line -Encoding string

				}

				Write-host "[+] Verifying and Saving Encrypted File..." -ForegroundColor Gray
				if(Test-Path $base64EncodeFilePath){Remove-Item $base64EncodeFilePath}
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
			$sizeEncipherBuffer = $encipherFileBuffer.Count
			
			
			if(-not $(Get-Variable -Name isEncipherFilePartial).IsValidValue($isEncipherFilePartial)){
				$isEncipherFilePartial = $($encipherFilePath.Split('enc')[1] -eq $($pt_ext.Split('enc')[1]+'.'+$inFileExt))
			}
			
			# For partial File Decryption
			if($isEncipherFilePartial){

				$partialEncFileBuffer = $($encipherFileBuffer | Select-Object -First $lineBufferSize)

				$dvs = [int]$partialEncFileBuffer.Count / 10

				forEach($line in $partialEncFileBuffer){
					$actual_pcnt = [int]$partialEncFileBuffer.indexOf($line) / $dvs

					# Show Progress
					Show-ProgressBar($actual_pcnt, "Decrypting ")
					$dec_line = $(python $(Join-Path . '\KeyCipher_stream_encrypter.py') --decrypt $key $line -m)  
											   
					Out-File -FilePath $decipherFilePath -Append  -InputObject $dec_line -Encoding string

				}

				$base64FileBufferRem = $($encipherFileBuffer | Select-Object -Last $($sizeEncipherBuffer - $lineBufferSize))
				Out-File -FilePath $decipherFilePath -Append  -InputObject $base64FileBufferRem -Encoding string

				# Clean up
				Write-host "[+] Removing temporary files..." -ForegroundColor Gray
				if(Test-Path $base64DecodeFilePath){Remove-Item $base64DecodeFilePath}
			}
			else
			{

			$divisor = [int]$sizeEncipherBuffer / 10

			# For full File Decryption
			forEach($line in $encipherFileBuffer)
			{
				$actual_pcnt = [int]$encipherFileBuffer.indexOf($line) / $divisor
				
				# Show Progress
				Show-ProgressBar($actual_pcnt, "Decrypting ")
				$dec_line = $(python $(Join-Path . '\KeyCipher_stream_encrypter.py') --decrypt $key $line -m)  
											   
				Out-File -FilePath $decipherFilePath -Append  -InputObject $dec_line -Encoding string

			}
			
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

function Show-ProgressBar($params){
	
	$act_pcnt = $params[0]
	$action = $params[1]

	$show_pcnt = [int]$($($act_pcnt) * 10)

	Write-Progress -Activity $($action+[string]$inputFileName)`
				   -Status $([string]$show_pcnt+"% Complete")`
				   -PercentComplete $($act_pcnt * 10)
}
