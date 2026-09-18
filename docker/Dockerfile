# meowkit-pio — PlatformIO + esptool for building/merging FeralCat firmware.
# Toolchain is cached in the named volume `meowkit-pio` mounted at
# /root/.platformio, so the ~1GB xtensa download happens only once.
FROM python:3.11-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      git build-essential ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir platformio esptool

WORKDIR /work
ENTRYPOINT ["pio"]
