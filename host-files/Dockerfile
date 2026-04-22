FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    vim \
    iputils-ping \
    hping3 \
    iproute2 \
    net-tools \
    curl \
    wget \
    nmap \
    tcpdump \
    dnsutils \
    netcat-openbsd \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /root/host-files

CMD ["bash"]
