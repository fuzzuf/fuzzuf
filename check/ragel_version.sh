#!/bin/bash
$1 -v|grep version|sed -e 's/.*version\s\+\([0-9.]\+\).*/\1/'

