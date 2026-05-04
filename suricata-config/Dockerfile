FROM jasonish/suricata:latest

USER root

WORKDIR /etc/suricata

RUN dnf install -y --allowerasing \
    vim \
    iproute \
    iputils \
    net-tools \
    iptables \
    wget \
    python3 \
    python3-pip \
    jq \
    && dnf clean all \
    && pip install pyinotify

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]