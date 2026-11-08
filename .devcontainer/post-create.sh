#!/bin/bash
set -ex

# Create Maven directory if it doesn't exist
mkdir -p ~/.m2
cp .devcontainer/settings.xml ~/.m2/settings.xml
