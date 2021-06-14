# escape=`
ARG InstallerRepo=mcr.microsoft.com/powershell
ARG InstallerVersion=latest

# Use server core as an installer container to extract PowerShell,
# As this is a multi-stage build, this stage will eventually be thrown away
FROM ${InstallerRepo}:$InstallerVersion AS install_invoke_keycipher

# Module enviromental variables
ENV saveDir=""

# Install python2.7 into alpine Server
# Install Invoke_KeyCipher Module
WORKDIR /module

COPY ./Invoke_KeyCipher.psm1 .
COPY ./base64 .
COPY ./KeyCipher_stream_encrypter.py .
COPY ./Invoke_KeyCipher.psd1 .

# creating input and output dirs
SHELL ["pwsh", "-Command"]
RUN mkdir -p ./etc/input ./etc/output`
    && mkdir -p /tmp/KeyCipher`
    && touch /tmp/KeyCipher/KeyCipher.log`
    && chmod 777 /tmp/KeyCipher/KeyCipher.log

 
# Installing python 2.7   
SHELL ["pwsh", "-Command"]
RUN $ProgressPreference = "SilentlyContinue"; $ErrorPreference = "Stop";`
    apt update;`
    apt-get install wget -y;`
    apt-get install git -y;`
    apt-get install python -y 

# Install Go compiler
SHELL ["pwsh", "-Command"]
RUN wget https://dl.google.com/go/go1.14.2.linux-amd64.tar.gz;`
    tar -C /usr/local -xzf go1.14.2.linux-amd64.tar.gz;

SHELL ["sh", "-c"]
RUN mkdir -p /module/go/src/base64 /module/go/bin /module/go/pkg`
    && export PATH=$PATH:/usr/local/go/bin`
    && alias go=/usr/local/go/bin/go`
    && GOROOT=/usr/local/go`
    && GOPATH=/module/go/`
    && export PATH=$PATH:$GOPATH/bin`
    && rm go1.14.2.linux-amd64.tar.gz

# compiling base64.go into an executable
SHELL ["pwsh", "-Command"]
RUN mv ./base64util.go ./go/src/base64;`
    sal go /usr/local/go/bin/go;`
    go get -v github.com/spf13/cobra;`
    go build /module/go/src/base64/base64util.go


ENTRYPOINT ["pwsh", "-Command", "Import-Module", "./Invoke_KeyCipher.psm1;", "Invoke-KeyCipher"]
