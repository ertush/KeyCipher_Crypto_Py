# escape=`

ARG InstallerRepo=mcr.microsoft.com/powershell
ARG InstallerVersion=latest

# Use server core as an installer container to extract PowerShell,
# As this is a multi-stage build, this stage will eventually be thrown away
FROM ${InstallerRepo}:$InstallerVersion 

# Install python2.7 into alpine Server
# Installing Invoke_KeyCipher Module


WORKDIR /module/dependencies/System32

SHELL ["pwsh", "-Command"]

RUN Set-PSRepository -InstallationPolicy Trusted -Name PSGallery;`
    Install-Module -Name Invoke_KeyCipher -RequiredVersion 0.1.1;`
    $env:windir="/module/dependencies";`
    apt-get update;`
    apt-get install python -y 

    
ADD ./certutil.exe .


CMD [ "pwsh" ]