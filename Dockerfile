FROM python:3.10-slim

RUN command apt-get update && \
    apt-get install -y golang git wget unzip && \
    rm -rf /var/lib/apt/lists/*


    ## set up Go environment variables and PATH

    ENV GOPATH=/root/go
    ENV PATH=$PATH:/usr/local/go/bin:$GOPATH/bin

    # install tools 

    RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest


    RUN nuclei -update-templates


    WORKDIR /app
    COPY . /app

    # install python dependencies

    RUN command pip install --no-cache-dir flask 

    EXPOSE 5000

    # tell to run web sever 

    CMD ["python", "app.py"]





