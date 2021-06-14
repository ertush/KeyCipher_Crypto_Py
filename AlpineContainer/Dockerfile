ARG InstallerRepo=mcr.microsoft.com/powershell
ARG InstallerVersion=lts-alpine-3.10

# Use server core as an installer container to extract PowerShell,
# As this is a multi-stage build, this stage will eventually be thrown away
FROM ${InstallerRepo}:$InstallerVersion AS install_invoke_keycipher

WORKDIR /module

COPY ./Invoke_KeyCipher.psm1 .
COPY ./base64 .
COPY ./KeyCipher_stream_encrypter.py .
COPY ./Invoke_KeyCipher.psd1 .

 # Installing python 2.7   
SHELL ["pwsh", "-Command"]
RUN $ProgressPreference = "SilentlyContinue"; $ErrorPreference = "Stop";\
    apk update ;\
    apk add wget  ;\
    apk add git ;\
    apk add python  

# Installing Go
SHELL ["pwsh", "-Command"]
RUN echo "installing go version 1.14.6...";\ 
    apk add --no-cache --virtual .build-deps bash gcc musl-dev openssl go;\ 
    wget https://dl.google.com/go/go1.14.6.linux-amd64.tar.gz;\ 
    tar -C /usr/local -xzf go1.14.6.linux-amd64.tar.gz;\ 
    cd /usr/local/go/src/;\ 
    ./make.bash 

SHELL ["sh", "-Command"]
RUN export PATH="/usr/local/go/bin:$PATH"\
    && export GOPATH=/opt/go/\
    && export PATH=$PATH:$GOPATH/bin\ 
    && apk del .build-deps\ 
    go version

# Creating input and output dirs
SHELL ["pwsh", "-Command"]
RUN mkdir -p ./etc/input ./etc/output\
    && mkdir -p /tmp/KeyCipher\
    && touch /tmp/KeyCipher/KeyCipher.log\
    && chmod 777 /tmp/KeyCipher/KeyCipher.log

# Clean Up dependencies
SHELL ["sh", "-c"]
RUN mkdir -p /module/go/src/base64 /module/go/bin /module/go/pkg\
    && rm go1.14.6.linux-amd64.tar.gz

# Compiling base64util.go 
SHELL ["pwsh", "-Command"]
RUN mv ./base64util.go ./go/src/base64;\
    sal go /usr/local/go/bin/go;\
    /usr/local/go/bin/go get -v github.com/spf13/cobra;\
    go build /module/go/src/base64/base64util.go

ENTRYPOINT ["pwsh", "-Command", "Import-Module", "./Invoke_KeyCipher.psm1;", "Invoke-KeyCipher"]