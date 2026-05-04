FROM jasonish/suricata:latest

USER root

WORKDIR /etc/suricata

RUN dnf install -y --allowerasing \
    vim \
    iproute \
    iputils \
    net-tools \
    wget \
    python3 \
    python3-pip \
    jq \
    iptables \
    && dnf clean all \
    && pip install pyinotify