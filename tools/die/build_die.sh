#!/bin/bash
#
# fuzzuf
# Copyright (C) 2021-2023 Ricerca Security
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see http://www.gnu.org/licenses/.
#
set -eux

TOOLS_DIE_DIR=$1

# URL
DIE_URL=https://github.com/sslab-gatech/DIE
DIE_DIR=DIE

# Commands
GIT=git
NPM=npm
TSC=tsc

##
# Loggin utility
##
COLOR_RED='\033[1;31m'
COLOR_GREEN='\033[1;32m'
COLOR_BOLD='\033[1m'
COLOR_NORMAL='\033[0m'
function info () {
    printf "${COLOR_BOLD}[*]${COLOR_NORMAL} $1\n"
}
function success () {
    printf "${COLOR_BOLD}${COLOR_GREEN}[+]${COLOR_NORMAL} $1\n"
}
function error () {
    printf "${COLOR_BOLD}${COLOR_RED}[-]${COLOR_NORMAL} $1\n"
}

##
# Check dependency
##

# git
if ! command -v $GIT &> /dev/null; then
    error "'$GIT' command not found"
    exit 1
fi

# npm
if ! command -v $NPM &> /dev/null; then
    error "'$NPM' command not found"
    exit 1
fi

##
# Build DIE
##

# Move to tools/die
cd $TOOLS_DIE_DIR

# Clone DIE
if [ ! -d "$DIE_DIR" ]; then
    info "Cloning ${DIE_URL}"
    $GIT clone $DIE_URL &> /dev/null
    if [ $? -ne 0 ]; then
        error "Could not clone DIE ('$GIT clone' failed)"
        exit 1
    fi
    success "DIE successfully cloned"
else
    info "DIE already exists. Skipping..."
fi

# Install node packages
(
    cd "$DIE_DIR/fuzz/TS"

    if [ ! -d "node_modules" ]; then
        info "Installing node modules..."
        $NPM install &> /dev/null
        if [ $? -ne 0 ]; then
            error "Could not install modules ('$NPM install' failed)"
            exit 1
        fi
        success "Node modules successfully installed"
    else
        info "Node modules already installed. Skipping..."
    fi
)

# Transpile TS
(
    cd "$DIE_DIR/fuzz/TS"

    if [[ -f "$DIE_DIR/fuzz/TS/esfuzz.js" && -f "$DIE_DIR/fuzz/TS/esfuzz.js" ]]; then
        info "Already transpiled. Skipping..."
    else
        info "Transpiling DIE..."
        node_modules/.bin/tsc
        if [ $? -ne 0 ]; then
            error "Could not transpile esfuzz"
            exit 1
        fi
        success "Transpile successfully done"
    fi
)

success "DIE successfully setup!"
