## Invoke_KeyCipher

  This powershell module is the ochestrator of the encryption and decryption done by ```KeyCipher_stream_encrypter.py```.
  It adds more features to the base encrypter / decrypter and acts as a wrapper for th python script.

  For more info and usage run ```powershell Get-Help Invoke-KeyCipher``` and ```powershell Get-help Invoke-KeyCipher -Example``` to see examples

  >>### Features
  >>* Supports lineSizeBuffers
  >>* Supports full and partial file Encryption/Decryption
  >>* Supports Pipline
  >>* Maintains a log file 

  >>### How to install
    Run ```powershell Install-Module -Name Invoke_KeyCipher -RequiredVersion 0.0.1``` then import it using ```powershell Import-Module -Path ${env:ProgramFiles(x86)}\WindowsPowershell\Modules\Invoke_KeyCipher\0.0.1\Invoke_KeyCipher.psm1```

  ## Dependencies
  * Certutil.exe
  * KeyCipher_stream_encrypter
  * base64.py
 
  ## Release Notes
   Version 0.0.1 only supports encryption of files less than 80 Mb of any format and type i.e all images formats, all video formats ,pem , exe etc. This is due to the limitation of the tool used to encode files (```Certutil.exe```). Future versions will however support encryption of any size of file

   You can also get the module from (powershellgallery)['https:\\powershellgallery.com'] by searching ```Invoke_KeyCipher```

## KeyCipher_stream_encrypter
 A file encrypting and password hashing tool in python.
  supports multiple Key Encryption.

``` 
Usage: KeyCipher [OPTIONS] [<int> | <string> KEY] [STRING]

OPTIONS         DEFINATION

=======         ==========

--encrypt       Mode for encryption
--decrypt       Mode for decryption
--help          Display help message
--keyMode       Multiple key encryption <'-m'>
```

## base64.py
This serves as an alternative to certutil for systems that dont have certutil.