FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -y \
  && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    dpdk \
    dpdk-dev \
    libssl-dev \
    yasm \
    iproute2 \
    iputils-ping \
    net-tools \
    ca-certificates \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
