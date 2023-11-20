#!/bin/bash
## Copyright (c) 2023, Grant Hernandez (https://github.com/grant-h)
## SPDX-License-Identifier: MIT
set -eu

if [ $# -ne 2 ]; then
  echo "usage: $0 modem.bin ghidra_project_path"
  exit 1
fi

FIRMWARE=$1
PROJECT=$2

echo "====> Building"
./gradlew

DISTS="./dist/*.zip"
DISTS=( $DISTS )

if [ ${#DISTS[@]} -ne 1 ]; then
  echo "Multiple dist ZIP files! Delete all but the latest"
  exit 1
fi

DIST="${DISTS[0]}"

BASE="$GHIDRA_INSTALL_DIR"
INSTALL_DIR="$BASE/Ghidra/Extensions/"

echo "====> Installing $DIST -> $INSTALL_DIR"

unzip -o "$DIST" -d "$INSTALL_DIR"

if [ ! -d "$PROJECT" ]; then
  echo "====> Making temporary Ghidra project $PROJECT"
  mkdir -p "$PROJECT"
else
  echo "====> Reusing Ghidra project $PROJECT"
fi

IMPORT_AS=$(basename "$FIRMWARE")
echo "====> Imported binary will be called $IMPORT_AS in $PROJECT"

echo "====> Running Ghidra headless for $FIRMWARE"
./scripts/ShannonFirmwareProcess.py "$PROJECT" "$IMPORT_AS" "$FIRMWARE"

exit 0
