FROM debian:sid
LABEL version="1.1"
LABEL description="WhatWaf Dockerized"
LABEL author="Ekultek"
COPY bootstrap.sh /tmp/bootstrap.sh
RUN chmod +x /tmp/bootstrap.sh
RUN bash -c /tmp/bootstrap.sh