#!/usr/bin/env bash

# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# Copyright © 2020 Intel Corporation
# Copyright (C) 2021-2023 Ricerca Security
# SPDX-License-Identifier: Apache-2.0

# Based on: https://github.com/cloud-hypervisor/cloud-hypervisor/blob/main/scripts/dev_cli.sh

CLI_NAME="fuzzuf"

CTR_REGISTRY="ghcr.io"
CTR_OWNER="fuzzuf/fuzzuf"
CTR_IMAGE_TAG="dev"
CTR_IMAGE_VERSION="latest"
CTR_IMAGE="$CTR_REGISTRY/$CTR_OWNER/$CTR_IMAGE_TAG:$CTR_IMAGE_VERSION"

DOCKER_RUNTIME="docker"

FUZZUF_SCRIPTS_DIR=$(cd "$(dirname "$0")" && pwd)
FUZZUF_ROOT_DIR=$(cd "${FUZZUF_SCRIPTS_DIR}/.." && pwd)
FUZZUF_BUILD_DIR="$FUZZUF_ROOT_DIR/build"
FUZZUF_DOCKERFILE="$FUZZUF_ROOT_DIR/Dockerfile"

CTR_SRC_ROOT_DIR="/src"
CTR_FUZZUF_ROOT_DIR="$CTR_SRC_ROOT_DIR/fuzzuf"

CTR_FUZZUF_BUILD_DIR="$CTR_FUZZUF_ROOT_DIR/build"
BUILD_TYPE="Debug"
RUNLEVEL="Debug"
DIE="1"
DOXYGEN="1"

PIN_BASE="pin-3.7-97619-g0d0c92f4f-gcc-linux"
PIN_NAME="$PIN_BASE.tar.gz"
PIN_URL="https://software.intel.com/sites/landingpage/pintool/downloads/$PIN_NAME"
PIN_PATH="$CTR_SRC_ROOT_DIR/$PIN_NAME"
PIN_ROOT="$CTR_SRC_ROOT_DIR/$PIN_BASE"

NODE_VERSION="17"

# Send a decorated message to stdout, followed by a new line
#
say() {
    [ -t 1 ] && [ -n "$TERM" ] \
        && echo "$(tput setaf 2)[$CLI_NAME]$(tput sgr0) $*" \
        || echo "[$CLI_NAME] $*"
}

# Send a decorated message to stdout, without a trailing new line
#
say_noln() {
    [ -t 1 ] && [ -n "$TERM" ] \
        && echo -n "$(tput setaf 2)[$CLI_NAME]$(tput sgr0) $*" \
        || echo "[$CLI_NAME] $*"
}

# Send a text message to stderr
#
say_err() {
    [ -t 2 ] && [ -n "$TERM" ] \
        && echo "$(tput setaf 1)[$CLI_NAME] $*$(tput sgr0)" 1>&2 \
        || echo "[$CLI_NAME] $*" 1>&2
}

# Send a warning-highlighted text to stdout
say_warn() {
    [ -t 1 ] && [ -n "$TERM" ] \
        && echo "$(tput setaf 3)[$CLI_NAME] $*$(tput sgr0)" \
        || echo "[$CLI_NAME] $*"
}

# Exit with an error message and (optional) code
# Usage: die [-c <error code>] <error message>
#
die() {
    code=1
    [[ "$1" = "-c" ]] && {
        code="$2"
        shift 2
    }
    say_err "$@"
    exit $code
}

# Exit with an error message if the last exit code is not 0
#
ok_or_die() {
    code=$?
    [[ $code -eq 0 ]] || die -c $code "$@"
}

# Send warning message if the last exit code is not 0
#
ok_or_warn() {
    code=$?
    [[ $code -eq 0 ]] || say_warn "$@"
}

# Make sure the build/ dirs are available. Exit if we can't create them.
# Upon returning from this call, the caller can be certain the build/ dirs exist.
#
ensure_build_dir() {
    for dir in "$FUZZUF_BUILD_DIR" ; do
        mkdir -p "$dir" || die "Error: cannot create dir $dir"
        [ -x "$dir" ] && [ -w "$dir" ] || \
            {
                say "Wrong permissions for $dir. Attempting to fix them ..."
                chmod +x+w "$dir"
            } || \
            die "Error: wrong permissions for $dir. Should be +x+w"
    done
}

# Make sure we're using the latest dev container, by just pulling it.
ensure_latest_ctr() {
    $DOCKER_RUNTIME pull "$CTR_IMAGE"

    ok_or_warn "Error pulling container image. Continuing."
}

# Fix main directory permissions after a container ran as root.
# Since the container ran as root, any files it creates will be owned by root.
# This fixes that by recursively changing the ownership of /src/fuzzuf to the
# current user.
#
fix_dir_perms() {
  # Yes, running Docker to get elevated privileges, just to chown some files
  # is a dirty hack.
  $DOCKER_RUNTIME run \
    --workdir "$CTR_FUZZUF_ROOT_DIR" \
    --rm \
    --volume "$FUZZUF_ROOT_DIR:$CTR_FUZZUF_ROOT_DIR" \
    "$CTR_IMAGE" \
    chown -R "$(id -u):$(id -g)" "$CTR_FUZZUF_ROOT_DIR"

    return $1
}

# Process exported volumes argument, separate the volumes and make docker compatible
# Sample input: --volumes /a:/a#/b:/b
# Sample output: --volume /a:/a --volume /b:/b
#
process_volumes_args() {
    if [ -z "$arg_vols" ]; then
        return
    fi
    exported_volumes=""
    arr_vols=(${arg_vols//#/ })
    for var in "${arr_vols[@]}"; do
        parts=(${var//:/ })
        if [[ ! -e "${parts[0]}" ]]; then
            echo "The volume ${parts[0]} does not exist."
            exit 1
        fi
        exported_volumes="$exported_volumes --volume $var"
    done
}

cmd_build-container() {
  ensure_build_dir
  # ensure_latest_ctr

  $DOCKER_RUNTIME build \
    -t "$CTR_IMAGE" \
    -f "$FUZZUF_DOCKERFILE" \
    --build-arg PIN_URL="$PIN_URL" \
    --build-arg PIN_PATH="$PIN_PATH" \
    --build-arg NODE_VERSION="$NODE_VERSION" \
    "$FUZZUF_ROOT_DIR"
}

cmd_build() {
  build_type="$BUILD_TYPE"
  runlevel="$RUNLEVEL"
  die="$DIE"
  doxygen="$DOXYGEN"
  while [ $# -gt 0 ]; do
    case "$1" in
            "-h"|"--help")  { cmd_help; exit 1; } ;;
            "--debug")      { build_type="Debug"; } ;;
            "--release")    { build_type="Release"; } ;;
            "--runlevel")
              shift
              [[ "$1" =~ ^(Debug|Release) ]] || \
                die "Invalid runlevel: $1. Valid options are \"Debug\" and \"Release\"."
                runlevel="$1"
                ;;
            "--no-die")     { die="0"; } ;;
            "--no-doxygen") { doxygen="0"; } ;;
            *)
              die "Unknown build argument: $1. Please use --help for help."
              ;;
	  esac
	  shift
  done

  ensure_build_dir
  # ensure_latest_ctr

  $DOCKER_RUNTIME run \
    --workdir "$CTR_FUZZUF_ROOT_DIR" \
    --rm \
    --volume "$FUZZUF_ROOT_DIR:$CTR_FUZZUF_ROOT_DIR" \
    "$CTR_IMAGE" \
    /bin/bash -c "set -eux \
    && cmake -B $CTR_FUZZUF_BUILD_DIR \
      -DCMAKE_BUILD_TYPE=$build_type \
      -DDEFAULT_RUNLEVEL=$runlevel \
      -DPIN_ROOT=$PIN_ROOT \
      -DENABLE_DOXYGEN=$doxygen \
    && cmake --build $CTR_FUZZUF_BUILD_DIR -j$(nproc)"

  if [[ "$die" = "1" ]]; then
    $DOCKER_RUNTIME run \
      --workdir "$CTR_FUZZUF_ROOT_DIR" \
      --rm \
      --volume "$FUZZUF_ROOT_DIR:$CTR_FUZZUF_ROOT_DIR" \
      "$CTR_IMAGE" \
      cmake --build $CTR_FUZZUF_BUILD_DIR --target die
  fi

  fix_dir_perms $?
}

cmd_clean() {
  ensure_build_dir
  # ensure_latest_ctr

  $DOCKER_RUNTIME run \
    --workdir "$CTR_FUZZUF_BUILD_DIR" \
    --rm \
    --volume "$FUZZUF_ROOT_DIR:$CTR_FUZZUF_ROOT_DIR" \
    "$CTR_IMAGE" \
    cmake --build $CTR_FUZZUF_BUILD_DIR --target clean

  fix_dir_perms $?
}

cmd_tests() {
  ensure_build_dir
  # ensure_latest_ctr

  $DOCKER_RUNTIME run \
    --workdir "$CTR_FUZZUF_BUILD_DIR" \
    --rm \
    --volume "$FUZZUF_ROOT_DIR:$CTR_FUZZUF_ROOT_DIR" \
    "$CTR_IMAGE" \
    cmake --build $CTR_FUZZUF_BUILD_DIR --target test

  fix_dir_perms $?
}

cmd_shell() {
  while [ $# -gt 0 ]; do
    case "$1" in
            "-h"|"--help")  { cmd_help; exit 1; } ;;
            "--volumes")
              shift
              arg_vols="$1"
              ;;
            "--") {
              shift
              break
            } ;;
            *) ;;
	  esac
	  shift
  done
  ensure_build_dir
  ensure_latest_ctr
  process_volumes_args

  say_warn "Starting a privileged shell prompt as root ..."
  say_warn "WARNING: Your $FUZZUF_ROOT_DIR folder will be bind-mounted in the container under $CTR_FUZZUF_ROOT_DIR"

  $DOCKER_RUNTIME run \
    -ti \
    --workdir "$CTR_FUZZUF_ROOT_DIR" \
    --rm \
    --volume "$FUZZUF_ROOT_DIR:$CTR_FUZZUF_ROOT_DIR" $exported_volumes \
    --env USER="root" \
    --entrypoint bash \
    "$CTR_IMAGE"

  fix_dir_perms $?
}

cmd_help() {
    echo ""
    echo "fuzzuf $(basename $0)"
    echo "Usage: $(basename $0) <command> [<command args>]"
    echo ""
    echo "Available commands:"
    echo ""
    echo "    build [--debug|--release] [--runlevel Debug|Release] [--no-die] [--no-doxygen]"
    echo "        Build the fuzzuf binaries."
    echo "        --debug               Build the debug binaries. This is the default."
    echo "        --release             Build the release binaries."
    echo "        --runlevel            Select default runlevel. Default is Debug."
    echo "        --no-die              Do not install DIE dependencies."
    echo "        --no-doxygen          Do not generate the Doxygen documents."
    echo ""
    echo "    tests"
    echo "        Run the fuzzuf tests."
    echo ""
    echo "    build-container"
    echo "        Build the fuzzuf container locally."
    echo ""
    echo "    clean"
    echo "        Remove the fuzzuf artifacts."
    echo ""
    echo "    shell"
    echo "        Run the development container into an interactive, privileged BASH shell."
    echo "        --volumes             Hash separated volumes to be exported. Example --volumes /mnt:/mnt#/myvol:/myvol"
    echo ""
    echo "    help"
    echo "        Display this help message."
    echo ""
}

# Parse main command line args.
#
while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)              { cmd_help; exit 1; } ;;
        -*)
            die "Unknown arg: $1. Please use \`$0 help\` for help."
            ;;
        *)
            break
            ;;
    esac
    shift
done

# $1 is now a command name. Check if it is a valid command and, if so,
# run it.
#
declare -f "cmd_$1" > /dev/null
ok_or_die "Unknown command: $1. Please use '$0 help' for help."

cmd=cmd_$1
shift

$cmd "$@"
