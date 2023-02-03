#!/usr/bin/env python
# -*-coding=utf-8 -*-
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
import json
import shlex
import subprocess
import sys
import re

def parse(output):
    records = {}
    pattern = re.compile(r"~~~TypeInfo:(<\d+,\d+,\d+>):(.+)")

    for l in output.split(b'\n'):
        l = l.strip().decode()

        # Parse output
        info = pattern.findall(l)
        if len(info) == 0:
            continue

        loc_info  = info[0][0] # Location of variable
        try:
            type_info = json.loads(info[0][1]) # Type information
        except json.decoder.JSONDecodeError:
            return {}

        # Record type for each variable (symbol in script)
        if not loc_info in records:
            # New symbol
            records[loc_info] = type_info

        else:
            if records[loc_info]['type'] == 'mixed':
                # Add type if already mixed
                for subType in records[loc_info]['extra']['subTypes']:
                    if subType == type_info:
                        # Type has been already recorded
                        break
                else:
                    # Otherwise record new type
                    records[loc_info]['extra']['subTypes'].append(type_info)

            elif records[loc_info] != type_info:
                # Mix types if type doesn't match to already existing one
                records[loc_info] = {
                    'type': 'mixed',
                    'extra': {'subTypes': [
                        type_info,
                        records[loc_info]
                    ]}
                }

            else:
                # Do nothing if type matches to already existing one
                pass

    return records

if __name__ == '__main__':
    if len(sys.argv) < 5:
        print("Usage: {} <d8_path> <d8_flags> <jsi_path> <type_path>".format(
            sys.argv[0]
        ))
        exit(1)

    cmd  = [sys.argv[1]]
    cmd += shlex.split(sys.argv[2])
    cmd += [sys.argv[3]]
    try:
        output = subprocess.check_output(cmd, timeout=30)
    except subprocess.TimeoutExpired as e:
        output = e.output
    except subprocess.CalledProcessError as e:
        output = e.output

    records = parse(output)
    if len(records) > 0:
        with open(sys.argv[4], "w") as f:
            f.write(json.dumps(records))

