#!/bin/bash
# Setup script for TLA+ VPS
# Run as: ghost@ladderscript
set -euo pipefail

echo "Installing Java 17..."
sudo apt-get update -qq
sudo apt-get install -y -qq openjdk-17-jre-headless

echo "Verifying Java..."
java -version

echo "Downloading tla2tools.jar..."
mkdir -p ~/tla
cd ~/tla
if [ ! -f tla2tools.jar ]; then
    wget -q https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar
fi

echo "Cloning bitcoin-core-ladder (spec directory only)..."
cd ~
if [ ! -d bitcoin-core-ladder ]; then
    git clone --depth 1 --filter=blob:none --sparse \
        git@github.com:bitcoin-ghost/bitcoin-core-ladder-script.git bitcoin-core-ladder
    cd bitcoin-core-ladder
    git sparse-checkout set spec
else
    cd bitcoin-core-ladder
    git pull
fi

echo ""
echo "Setup complete. To run:"
echo "  cd ~/bitcoin-core-ladder/spec/consensus"
echo "  JAVA=/usr/bin/java TLA2TOOLS=~/tla/tla2tools.jar ./run-all.sh"
echo ""
echo "System: $(free -h | grep Mem | awk '{print $2}') RAM, $(nproc) cores"
