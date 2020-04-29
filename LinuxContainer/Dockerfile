# escape=`

ARG InstallerRepo=mcr.microsoft.com/powershell
ARG InstallerVersion=latest

# Use server core as an installer container to extract PowerShell,
# As this is a multi-stage build, this stage will eventually be thrown away
FROM ${InstallerRepo}:$InstallerVersion 

# Install python2.7 into alpine Server
# Installing Invoke_KeyCipher Module

SHELL ["pwsh", "-Command"]

RUN Set-ExecutionPolicy -ExecutionPolicy Bypass;`
    Set-PSRepository -InstallationPolicy Trusted -Name PSGallery;`
    Install-Module -Name Invoke_KeyCipher -RequiredVersion 0.1.3 -Force;`
    apt-get update;`
    apt-get install python -y 
    
CMD [ "pwsh" ]