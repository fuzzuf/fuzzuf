#!/bin/bash

DIR=`dirname ${0}`
export PYTHONPATH=${1}
${DIR}/gen_graph.py ${2}
