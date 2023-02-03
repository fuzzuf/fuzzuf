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
if [ -z "${3}" ]
then
  echo "引数が足りない" >&2
  exit 1
fi

PYENV_NAME=${1}
PYENV_ROOT=${2}
BUILD_DIR=${3}

function die(){
  echo $@ >&2
  exit 1
}

mkdir -p ${BUILD_DIR}
if [ "${PYENV_NAME}" != "native" ]
then
  BUILD_SUFFIX=${PYENV_NAME}-$(echo ${PYENV_ROOT}|sha256sum|sed -e 's/\s\+.*//')
  if [ ! -d "${PYENV_ROOT}" ]
  then
    git clone --depth 1 https://github.com/pyenv/pyenv.git ${PYENV_ROOT} || die "pyenvをcloneできない"
  fi
  export PYENV_ROOT="${PYENV_ROOT}"
  export PATH="${PYENV_ROOT}/bin:${PATH}"
  eval "$(pyenv init -)"
  CFLAGS="-fPIC" PYTHON_CONFIGURE_OPTS="--enable-shared" pyenv install -s ${PYENV_NAME} || die "Python-${PYENV_NAME}をインストールできない"
  pyenv local ${PYENV_NAME} || die "Python-${1}に切り替えられない"
  mkdir -p ${BUILD_DIR}-${BUILD_SUFFIX}
  pushd ${BUILD_DIR}-${BUILD_SUFFIX}
  cmake ../ ${@:4} || die "cmakeできない"
  make -j8 || die "makeできない"
  CTEST_OUTPUT_ON_FAILURE=1 make test || die "testが失敗した"
else
  unset PYENV_NAME
  pushd ${BUILD_DIR}
  cmake ../ ${@:4} || die "cmakeできない"
  make -j8 || die "makeできない"
  CTEST_OUTPUT_ON_FAILURE=1 make test || die "testが失敗した"
  make fuzzuf_doc >doxygen.log || die "ドキュメントを作れない"
  make package || die "パッケージを作れない"
  COMMIT_ID=$(git log --format="%H" -n 1)
  pushd docs
  if [ -e '.git' ]
  then
    git config user.email "ricsec-bot@ricsec.co.jp"
    git config user.name "ricsec-bot"
    mkdir -p docs
    pushd docs
    rm -rf *
    mv ../../html/* ./
    git add *
    popd
    date >last_update
    git add last_update
    git commit -a -m "Generated from ${COMMIT_ID}"
  fi
  popd
  popd
fi

