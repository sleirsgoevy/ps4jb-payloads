#!/usr/bin/env bash

git submodule update --init --recursive || exit 1
cd ps5-kstuff
make
cd ..
cd ps5-kstuff-ldr
make
