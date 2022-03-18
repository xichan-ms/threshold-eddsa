#!/bin/sh

set -e


if [ ! -f "build/env.sh" ]; then #-f FILE exists and is a regular file
    echo "$0 must be run from the root of the repository."
    exit 2
fi

# Create fake Go workspace if it doesn't exist yet.
workspace="$PWD/build/_workspace"
root="$PWD"
dir="$workspace/src/github.com/jnxchang"

if [ ! -L "$dir/go-thresholdeddsa" ]; then	#-L FILE exists and is a symbolic link (same as -h)
    mkdir -p "$dir"
    cd "$dir"
    ln -sv ../../../../../. go-thresholdeddsa
    cd "$root"
fi

# Set up the environment to use the workspace.
GOPATH="$workspace"
export GOPATH

# Run the command inside the workspace.
cd "$dir/go-thresholdeddsa"
PWD="$dir/go-thresholdeddsa"

# Launch the arguments with the configured environment.
exec "$@"
