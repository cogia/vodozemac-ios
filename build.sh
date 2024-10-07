#!/bin/bash

cargo build
cbindgen --config cbindgen.toml --lang c --crate vodozemac-ios --output vodozemac_ios.h