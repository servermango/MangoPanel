FROM litespeedtech/openlitespeed:latest
RUN apt-get update && apt-get install -y lsphp82 lsphp83 lsphp84 \
    lsphp82-mysql lsphp83-mysql lsphp84-mysql \
    lsphp82-curl lsphp83-curl lsphp84-curl \
    && rm -rf /var/lib/apt/lists/*
