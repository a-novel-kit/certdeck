#!/bin/bash

TEST_TOOL_PKG="gotest.tools/gotestsum@latest"

# Execute tests.
go run ${TEST_TOOL_PKG} --format pkgname -- -count=1 -coverprofile=cover.out -p 1 $(go list ./... | grep -v /mocks | grep -v /internal)
go tool cover -html=cover.out -o cover.html
