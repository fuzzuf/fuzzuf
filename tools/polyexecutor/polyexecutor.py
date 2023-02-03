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
import subprocess
import os
from polytracker import PolyTrackerTrace, taint_forest
from polytracker.database import DBProgramTrace, CanonicalMap, DBReferencedValue
from polytracker.tracing import ByteAccessType

import argparse

class PolyExecutor:
    def __init__(self, cmd, input, db, debug):
        if os.path.basename(cmd[0]) == cmd[0]:
            ### If cmd[0] is same as file name, prefix with current directory
            cmd[0] = os.path.join(os.getcwd(), cmd[0])
        self.cmdline = " ".join(cmd).replace("@@", input)
        self.input = input
        self.db = db
        self.env = os.environ.copy()
        self.env["POLYPATH"] = input
        self.env["POLYTRACE"] = "1"
        self.env["POLYDB"] = db
        self.debug = debug
        
    def run(self):        
        print("[PolyExecutor] cmdline = {}".format(self.cmdline))
        proc = subprocess.Popen(self.cmdline, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env = self.env, shell=True)
        stdout, stderr = proc.communicate()
        proc.wait()  
        if self.debug:      
            print(stdout)
            print(stderr)
            # print(proc.returncode)
        return 128-proc.returncode

class TaintForest:
    def __init__(self, trace: DBProgramTrace):
        self.canonical_map = {} # : label |-> [offset]
        for entry in trace.session.query(CanonicalMap).all():
            if entry.taint_label in self.canonical_map:
                self.canonical_map[entry.taint_label] += [entry.file_offset]
            else:
                self.canonical_map[entry.taint_label] = [entry.file_offset]

        def process_taint_forest_node(taint_forest, node):
            if node is None:
                return None
            if isinstance(node, int):
                return node

            taint_forest[node.label] = (
                process_taint_forest_node(taint_forest, node.parent_one_id), 
                process_taint_forest_node(taint_forest, node.parent_two_id)
                )
            return node.label

        self.taint_forest = {} # : label |-> (parent1 : label, parent2 : label)
        for node in trace.taint_forest:
            process_taint_forest_node(self.taint_forest, node)

    def origins(self, label):
        if label == 0 or label is None:
            # Fail safe
            return []
        
        parent = self.taint_forest[label]
        if parent == (0, 0):
            return [label]
        else:
            return self.origins(parent[0]) + self.origins(parent[1])

    def offsets(self, label):
        res = []
        for origin in self.origins(label):
            res += self.canonical_map.get(origin, [])
        return res
        
    def __repr__(self) -> str:
        return "{\n" + \
            "\ttaint_forest: [\n{}\t]\n".format("".join([f"\t\t{k} |-> {v}\n" for (k, v) in self.taint_forest.items()])) + \
            "\tcanonical_map: [\n{}\t]\n".format("".join([f"\t\t{k} |-> {v}\n" for (k, v) in self.canonical_map.items()])) + \
            "}"

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='libdft64 compatible taint analysis')
    parser.add_argument("-c", "--cmd", help="PUT command line", nargs='+', required=True)
    parser.add_argument("-i", "--input", help="Path to input file for PUT", required=True)
    parser.add_argument("-o", "--output", help="Path to directory in which *.out files put", required=True)
    parser.add_argument("-d", "--db", default="polytracker.db")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    executor = PolyExecutor(args.cmd, args.input, args.db, args.debug)
    if executor.run() < 0:
        print("Failed to run taint analysis")
        exit(1)
    
    trace = PolyTrackerTrace.load(args.db)

    taint_forest = TaintForest(trace)
    if args.debug:
        print(f"[*] taint_forest: {taint_forest!r}") # DEBUG:  

    # print("[*] Referenced values")
    # for ref in trace.referenced_values:
    #     print(ref)

    taint_file = open(args.output, "w+")

    ### NOTE: Assuming there is only one input file for taint analysis
    print("[*] CMP/LEA analysis")
    for access in trace.access_sequence():
        if access.access_type == ByteAccessType.CMP_ACCESS:
            referenced_value = trace.session.query(DBReferencedValue).filter(DBReferencedValue.event_id == access.event_id).all()
            if referenced_value:
                # import ipdb; ipdb.set_trace()
                offset_str = ','.join([f"{offset:#x}" for offset in taint_forest.offsets(access.label)])
                value_str = ','.join([f"{ref.value:#x}" for ref in referenced_value])
                print("CMP(event_id={event_id}, function={function}, bb_index={bb_index}): Offset [{offset}] (label {label}) <-> Value [{value}]".format(
                    event_id=access.event.event_id,
                    function=access.event.function.name,
                    bb_index=access.event.bb_index,
                    offset=offset_str,
                    label=access.label,
                    value=value_str
                    ))
                taint_file.write("CMP {offset} {value}\n".format(offset=offset_str, value=value_str))
        elif access.access_type == ByteAccessType.MEMORY_ACCESS_OPERAND_ACCESS:
            offset_str = ','.join([f"{offset:#x}" for offset in taint_forest.offsets(access.label)])
            print("LEA(event_id={event_id}, function={function}, bb_index={bb_index}): Offset [{offset}] (label {label})".format(
                event_id=access.event.event_id,
                function=access.event.function.name,
                bb_index=access.event.bb_index,
                offset=offset_str,
                label=access.label,
            ))
            taint_file.write("LEA {offset} {value}\n".format(offset=offset_str, value=""))

    taint_file.close()
    os.remove(args.db) # We should remove the taint db at every execution
