FROM python:3.10-slim

Run apt-get update && \
    apt-get install -y golang git wget unzip && \
    rm -rf /var/lib/apt/lists/*


    ## set up Go environment variables and PATH

    ENV GOPATH=/root/go
    ENV PATH=$PATH:/usr/local/go/bin:$GOPATH/bin

    # install tools 