# escape=`
ARG InstallerRepo=mcr.microsoft.com/powershell
ARG InstallerVersion=latest
ARG Invoke_KeyCipher_dir=/root/.local/share/powershell/Modules/Invoke_KeyCipher/0.1.3.1/Invoke_KeyCipher.psm1

# Use server core as an installer container to extract PowerShell,
# As this is a multi-stage build, this stage will eventually be thrown away
FROM ${InstallerRepo}:$InstallerVersion 

# Install python2.7 into alpine Server
# Installing Invoke_KeyCipher Module

SHELL ["pwsh", "-Command"]

RUN $ProgressPreference = "SilentlyContinue"; $ErrorPreference = "Stop";`
    Install-Module -Name Invoke_KeyCipher -RequiredVersion 0.1.3.1 -Force -Verbose;`
    apt-get update;`
    apt-get install python -y 

# RUN Import-Module Invoke_KeyCipher_dir -Verbose
CMD ["pwsh"]