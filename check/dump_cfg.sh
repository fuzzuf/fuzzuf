#!/bin/bash

DIR=`dirname ${0}`
echo ${1} ${2}
export PYTHONPATH=${1}
${DIR}/dump_cfg.py ${2}
