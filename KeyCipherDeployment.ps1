param(
[Parameter(position = 1, mandatory = $true)] [String] $inFilePath,
[Parameter(position = 2, mandatory = $true)] [String] $outFilePath,
[Parameter(position = 3, mandatory = $true)] [String] $key,
[Parameter(position = 4)] [Switch] $keyMode,
[Parameter(position = 5, mandatory = $true)] [String] $mode
)

$ErrorActionPreference = "Silently Continue"
$isCertUtil = $($(ls $env:windir\System32 | ?{$_.name -like "certUti*"} | select Name | %{$_.name}) -eq "certutil.exe")
#sal  KeyCipher_modified $(Join-path "H:\Code\" "KeyCipher_old_modified.py")
#sal Find  $(Join-path .\ "Find.ps1")
sal certutil $(Join-path $env:windir "\System32\certutil.exe")
$inputFileName = $(@($inFilePath.split('\'))[@($inFilePath.split('\')).count - 1])
$base64EncodeFilePath = $(Join-path $outFilePath "Encoded.bs64enc")
$bsDecodeName = $inputFileName.replace(".",".dec64.")
$base64DecodeFilePath = $(Join-path $outFilePath $bsDecodeName)
$encipherFilePath = $(Join-path $outFilePath "Enciphered.enc")
$decipherFilePath = $(Join-path $outFilePath "Deciphered.dec")
$LogPath = ""


function base64Encode(){
if($isCertUtil){
#if(fileExist($inputFileName, $inFilePath)){
certutil -encode $inFilePath $base64EncodeFilePath
#}
#else{
#"["+$(date)+"] :: ERROR :: File Not Found ("+ $inFilePath + ").`n" >> $LogPath
#}
}
else{
"["+$(date)+"] :: ERROR :: File Not Found (certutil.exe).`n" >> $LogPath
}
}

function base64Decode(){
$isdecipherFilePath = $($(ls $decipherFilePath | select length | %{$_.length}) -gt 0)
#fileExist("Deciphered.dec", $decipherFilePath)
if($isCertUtil){
if($isdecipherFilePath){
certutil -decode $decipherFilePath $base64DecodeFilePath
}
else{
"["+$(date)+"] :: ERROR :: File Not Found ("+ $decipherFilePath +").`n" >> $LogPath
}
}
else{
"["+$(date)+"] :: ERROR :: File Not Found (certutil.exe).`n" >> $LogPath
}
}

function encipherFile(){
$isBase64EncodeFilePath = $($(ls $base64EncodeFilePath | select length | %{$_.length}) -gt 0)
#fileExist("Encoded.bs64enc", $base64EncodeFilePath)
if($isBase64EncodeFilePath){
   #if($(gal python | select name | %{$_.name}) -eq "python"){
   
	if($keyMode){	
	python 'H:\Code\KeyCipher_old_modified.py' --encrypt $key $base64EncodeFilePath  $encipherFilePath -m 
	}
#}
}
else{
"["+$(date)+"] :: ERROR :: File Not Found ("+ $base64EncodeFilePath +").`n" >> $LogPath
}
}

function decipherFile(){
$isEncipherFilePath = $($(ls $encipherFilePath | select length | %{$_.length}) -gt 0)
#fileExist("Enciphered.enc", $encipherFilePath)
if($isEncipherFilePath){

	if($keyMode){	
	python 'H:\Code\KeyCipher_old_modified.py' --decrypt $key $encipherFilePath  $decipherFilePath -m 
	}
	
}
else
{
"["+$(date)+"] :: ERROR :: File Not Found ("+ $encipherFilePath +").`n" >> $LogPath
}

}

#function fileExist($file,$path){
#if($($(Find $path $file) | select name | %{$_.name}) -match $null){
#return $false
#}
#else{
#return $($(Find $path $file) | select name | %{$_.name}) -match $file
#}
#}



function main(){
#if(-not $(fileExist("KeyCipherError.log",$env:TEMP))){
if( -not $(Join-path $env:TEMP "\KeyCipher")){
 mkdir  $(Join-path $env:TEMP "\KeyCipher")
 $LogPath = $(Join-path $env:TEMP "\KeyCipher\KeyCipherError.log")
 }
 $LogPath = $(Join-path $env:TEMP "\KeyCipher\KeyCipherError.log")
#}
if ($mode -eq "encrypt"){
	base64Encode
	encipherFile	
}
if ($mode -eq "decrypt")
	{
	decipherFile
	base64Decode
	
	}
	
}

main