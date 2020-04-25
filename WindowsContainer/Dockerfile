#escape = `


# Indicates that the windowsservercore image will be used as the base image.
# tag 1903
FROM mcr.microsoft.com/windows/servercore:ltsc2019 

# Metadata indicating an image maintainer.
LABEL maintainer="eromtush@gmail.com"

# Installing the Invoke_KeyCipher Module
RUN powershell -Command Set-ExecutionPolicy Bypass -Scope Process -Force;`
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force;`
    Install-Module -Name Invoke_KeyCipher -RequiredVersion 0.1.1 -Force;

# Installing Chocolatey and python
RUN powershell -Command Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'));`
    choco install python2 -y;`
    RefreshEnv.cmd;

# Sets a command or process that will run each time a container is run from the new image.
CMD [ "powershell" ]