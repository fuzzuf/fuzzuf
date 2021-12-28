 # Copyright (C) 2017
 #
 # Written by Ashley Lesdalons <ashley.lesdalons@etu.univ-grenoble-alpes.fr>
 #
 # ========LICENCE========
 # This script is free software: you can redistribute it and/or modify
 # it under the terms of the  GNU Lesser General Public
 # License as published by the Free Software Foundation; either
 # version 2.1 of the License, or (at your option) any later version.
 #
 # This script is distributed in the hope that it will be useful,
 # but WITHOUT ANY WARRANTY; without even the implied warranty of
 # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 # Lesser General Public License for more details.
 #
 # You should have received a copy of the GNU Lesser General Public
 # License along with this script; if not, write to the Free Software
 # Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 # ========LICENCE========

import angr
import copy
import pickle
import ntpath
import sys
from capstone import *
from capstone.x86_const import X86_INS_CMP, X86_OP_IMM
import networkx as nx
from angrutils import plot_cfg


cmp_imm_operands = set()
fweight = dict()
nweight = dict()

def calculate_weight_edges(cfg):
	for node in cfg.graph.nodes():
		successors = cfg.model.get_successors(node,excluding_fakeret=True)
		if len(successors) == 0: continue
		weight = 1.0 / len(successors)
		for s in successors:	# an undirect jump/call represented by PathTerminator can have up to 250 successors
			if s.name == "PathTerminator":
				weight = 1.0
		# assign weight to each outgoing edge
		for s in successors:
			cfg.graph.adj[node][s]['weight'] = weight

def calculate_weight_blocks(cfg):
	global fweight
	global nweight
	nodes_done = 0
	total_nodes = len(cfg.graph.nodes())
	print(total_nodes)
	stuck = 0 	# this variable increases if the algorithm is stuck
	fin_nodes = set()
	while nodes_done < total_nodes:
		stuck += 1
		if stuck >= 2*total_nodes:
			#print("stuck at %d (%d/%d)" % (stuck, nodes_done, total_nodes))
			#print(fin_nodes)
			#not_yet = set([hex(n.addr) for n in cfg.graph.nodes()]) - fin_nodes
			#print(not_yet)
			algo_stuck(cfg)
		for current_node in cfg.graph.nodes():
			#print("predcessors of 0x%X node" % current_node.addr)			
			predecessors = cfg.model.get_predecessors(current_node,excluding_fakeret=True)
			#print(predecessors)
			#print([(hex(k), v) for k,v in nweight.items()])
			#if current_node.addr in nweight: 
			#	continue
			
			if len(predecessors) == 0: # if node has no predecessor, then it's a function call or an orphan
				if current_node.addr in fweight:
					nweight[current_node.addr] = fweight[current_node.addr][0] 
				else:
					nweight[current_node.addr] = 1.0
				nodes_done += 1
				fin_nodes.add(hex(current_node.addr))
				stuck = 0 # we made some progress, not stuck
				continue
			a = True
			for pnode in predecessors:
				a = a and (pnode.addr in nweight)
			if a:
				nweight[current_node.addr] = 0.0
				nodes_done += 1
				fin_nodes.add(hex(current_node.addr))
				stuck = 0 # we made some progress, not stuck
				for pnode in predecessors:
					nweight[current_node.addr] += cfg.graph.adj[pnode][current_node]["weight"] * nweight[pnode.addr]
			else:
				print("predcessors of 0x%X node are not found" % current_node.addr)
				print(predecessors)

def algo_stuck(cfg):
	print("   The algorithm is stuck. There is probably at least one loop in the CFG.")
	print("   A graphical view of the CFG will be generated in %s_cfg.png" % cfg.name)
	try:
		plot_cfg(cfg,"%s_cfg" % cfg.name,asminst=True, vexinst=False, debug_info=False, remove_imports=True, remove_path_terminator=False)
		print("   PNG generated sucessfully")
	except:
		print("   PNG generation failed. It is printed below:")
	printCFG(cfg)
	sys.exit(1)

def remove_cycles(cfg):
	removed_edges = []
	# we remove loops with only one node
	tmp = copy.deepcopy(cfg.graph.edges())
	for n1,n2 in tmp:		
		if n1 == n2:
			cfg.graph.remove_edge(n1,n2)
			removed_edges.append((n1,n2))
	# it removes complex cycles with more than 2 nodes
	while True:
		try:
			cycle = nx.find_cycle(cfg_f.graph)
			for i in range(1,len(cycle)+1):
				n1,n2 = cycle[-i]
				if len(cfg.model.get_predecessors(n2,excluding_fakeret=True)) > 1:
					removed_edges.append((n1,n2))
					cfg.graph.remove_edge(n1,n2)
					break
				# if no edge has been removed, by default we remove the last one
				n1,n2 = cycle[-1]
				removed_edges.append((n1,n2))
				cfg.graph.remove_edge(n1,n2)
		except:
			break
	# we remove simple loops with more than 2 nodes
	while True:
		try:
			loop = nx.simple_cycles(cfg.graph).next()
		except:
			break
		if len(loop) == 1: continue	# WORKAROUND
		for i in range(1,len(loop)):
			n1 = loop[-i-1]
			n2 = loop[-i]
			if cfg.graph.has_edge(n1,n2):	# WORKAROUND
				if len(cfg.model.get_predecessors(n2,excluding_fakeret=True)) > 1:
					removed_edges.append((n1,n2))
					cfg.graph.remove_edge(n1,n2)
					break
		# if no edge has been removed, by default we remove the last one
		try:
			n1 = loop[-2]
			n2 = loop[-1]
			removed_edges.append((n1,n2))
			cfg.graph.remove_edge(n1,n2)
		except:
			pass
	# print info
	if len(removed_edges) == 0:
		print("   ==> No cycles found")
	else:
		print("   ==> %d cycles found" % len(removed_edges))
		for n1,n2 in removed_edges:
			print("    0x%x (%s) --> 0x%x (%s)" % (n1.addr,n1.name,n2.addr,n2.name))

def remove_cycles_callgraph(callgraph):
	removed_edges = []
	while True:
		try:
			loop = nx.simple_cycles(callgraph.graph).next()
		except:
			break
		if len(loop) == 1: continue	# WORKAROUND
		for i in range(1,len(loop)):
			n1 = loop[-i-1]
			n2 = loop[-i]
			if callgraph.graph.has_edge(n1,n2):	# WORKAROUND
				if len(callgraph.predecessors(n2)) > 1:
					removed_edges.append((n1,n2))
					callgraph.graph.remove_edge(n1,n2)
					break
		# if no edge has been removed, by default we remove the last one
		try:
			n1 = loop[-2]
			n2 = loop[-1]
			removed_edges.append((n1,n2))
			callgraph.graph.remove_edge(n1,n2)
		except:
			pass

def remove_pathterminator(cfg):
	for node in cfg.graph.nodes():
		if node.name == "PathTerminator":
			cfg.graph.remove_node(node)
	for n1,n2 in cfg.graph.edges():
		if n1.name == "PathTerminator" or n2.name == "PathTerminator":
			cfg.graph.remove_edge(n1,n2)

def printCFG(cfg):
	print("===== CFG of %s =====" % cfg.name)
	print("== Nodes ==")
	for n in cfg.graph.nodes():
		if n.addr in nweight:
			print("%s (0x%x)  weight=%.02f" % (n.name,n.addr,nweight[n.addr]))
		else:
			print("%s (0x%x)" % (n.name,n.addr))
	print("== Edges ==")
	for n1,n2 in cfg.graph.edges():
		if "weight" in cfg.graph.adj[n1][n2]:
			print("0x%x (%s) --%.2f-->  0x%x (%s)" % (n1.addr,n1.name,cfg.graph.adj[n1][n2]["weight"],n2.addr,n2.name))
		else:
			print("0x%x (%s) -->  0x%x (%s)" % (n1.addr,n1.name,n2.addr,n2.name))
	print("")
		
def dump_analysis(filename):
	global fweight,cmp_imm_operands		
	for addr in fweight:
		a,b = fweight[addr]
		fweight[addr] = (1.0/a,b)
	print(fweight)
	with open("weight","w") as f:
		for k, v in fweight.items():
			f.write("{} {} {}\n".format(k, v[0], v[1]))
		
	# dump cmp operands analysis
	cmp_imm_operands_hex = []
	cmp_imm_operands2 = list(cmp_imm_operands)
	for op in cmp_imm_operands2:
		cmp_imm_operands_hex += [op[i:i+2] for i in range(2,len(op),2)]
		if len(op) == 3:
			cmp_imm_operands.remove(op)
	cmp_imm_operands_hex = set().union(cmp_imm_operands_hex)
	print((cmp_imm_operands,cmp_imm_operands_hex))

	with open("%full.dict" % filename,'w') as f:
		f.write("# This dicitonary is automatically generated by bb-weight script.\n")
		for i, b in enumerate(cmp_imm_operands):
			f.write("label_{idx}=\"{byte}\"\n".format(idx=i, byte=b))

	with open("%unique.dict" % filename,'w') as f:
		f.write("# This dicitonary is automatically generated by bb-weight script.\n")
		for i, b in enumerate(cmp_imm_operands_hex):
			f.write("label_{idx}=\"{byte}\"\n".format(idx=i, byte=b))

def find_CMP_operands(proj,cfg,binName):
	global cmp_imm_operands
	for node in cfg.graph.nodes():
		for inst in node.instruction_addrs:
			insns = proj.factory.block(inst,num_inst=1).capstone.insns
			#print(insns)
			if (len(insns) == 0):
				continue
			insn = insns[0].insn
			if insn.mnemonic == "cmp":
				for op in insn.operands:
					if op.type == X86_OP_IMM:
						cmp_imm_operands.add("0x%X" % op.value.imm)

if __name__ == "__main__":
	binaryPath = sys.argv[1]
	binName = ntpath.basename(binaryPath)
	print("[+] Opening binary %s" % binaryPath)
	proj = angr.Project(binaryPath,load_options={'auto_load_libs': False,'main_opts': {'custom_base_addr': 0x0}})
	
	print("[+] Searching for all the functions (using CFGFast)")
	full_cfg = proj.analyses.CFGFast(show_progressbar=True)
	
	# we want to only keep functions defined in the main binary
	functions = []
	for addr,func in full_cfg.functions.items():
		if proj.loader.main_object.contains_addr(addr) and addr not in proj.loader.main_object.reverse_plt:
			functions.append((addr,func))

	nb_functions = len(functions)
	print("   ==> %d functions to process." % nb_functions)

	callgraph = full_cfg.functions.callgraph
	remove_cycles_callgraph(callgraph)

	i=1
	stuck = 0
	while len(functions) > 0:
		for addr,func in functions:
			stuck += 1
			if stuck < 2*len(functions):	# Security precaution, in case the call graph still contains loops
				if callgraph.has_node(addr): # sometimes the function isn't in the call graph
					predecessors = callgraph.predecessors(addr)
					if len([a for a in functions if a[0] in predecessors]) > 0:
						continue
			stuck = 0

			print("[+] (%d/%d) Computing Accurate CFG for function %s (0x%x)" % (i,nb_functions,func.name,addr))
			functions.remove((addr,func))
			i+=1
			cfg_f = proj.analyses.CFGEmulated(
				#max_iterations=5,
				starts=[addr], 
				context_sensitivity_level=1, 
				call_depth=0, 
				normalize=True,
				enable_symbolic_back_traversal=True,
				#enable_advanced_backward_slicing=True
			)
			cfg_f.remove_cycles()	# works if max_iteration has a high value but then CFGAccurate becomes very slow
			cfg_f.name = func.name
			
			print("   [+] Removing cycles")
			remove_cycles(cfg_f)	# remove the loop-back edges

			print("   [+] Searching for CMP operands")
			find_CMP_operands(proj,cfg_f,binName)
			
			print("   [+] Computing edges/vertices weight")
			calculate_weight_edges(cfg_f)
			calculate_weight_blocks(cfg_f)
			
			# store data in export in fweight
			for node in cfg_f.graph.nodes():
				if node.addr in fweight:
					w,e = fweight[node.addr]
					fweight[node.addr] = (min(w,nweight[node.addr]),e)
				else:
					if node.size is not None:	# WORKAROUND: sometimes, the size is None for some reason :-(
						fweight[node.addr] = (nweight[node.addr],node.addr+node.size)
					else:
						fweight[node.addr] = (nweight[node.addr],-1)

			del cfg_f
			break
	
	print("[+] Dumping analysis to pickle files")
	dump_analysis(binName)
	
	print("[+] Done.")
