#!/bin/bash

DIR=`dirname ${0}`
export PYTHONPATH=${1}
${DIR}/gen_dyn_weight.py
