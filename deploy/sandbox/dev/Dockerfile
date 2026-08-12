# syntax=docker/dockerfile:1.7
# OpenBox dev sandbox — wraps the NVIDIA OpenShell base image with
# Python, Git, and curl. Built locally by obs provision --dev.
# Published as a GitHub release asset (docker save .tar), not a registry.
FROM ghcr.io/nvidia/openshell-community/sandboxes/base@sha256:aeef1c63f00e2913ea002ccb3aaf925f338b5c5d70e63576f0d95c16a138044e

USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip \
    git \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*
USER sandbox

LABEL org.opencontainers.image.title="OpenBox dev sandbox" \
      org.opencontainers.image.description="NVIDIA OpenShell base + Python, Git, curl"
