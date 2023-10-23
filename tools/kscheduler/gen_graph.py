#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import tempfile
import argparse
import subprocess
import pickle
import copy
from collections import defaultdict
import networkit as nk

sys.setrecursionlimit( 50000 )

def detect_back_edge(graph):
  visited = set()
  back_edge = []
  def dfs(node, path):
    for nei in graph[node]:
      if nei not in visited:
        visited.add(nei)
        path.add(nei)
        dfs(nei, path)
        path.remove(nei)

      # detect back edge
      elif nei in path:
        back_edge.append((node, nei))

  cnt = 0
  for node,_ in graph.items():
    if node not in visited:
      visited.add(node)
      cur_path = set()
      cur_path.add(node)
      dfs(node, cur_path)
      cnt+=1

  return back_edge, cnt

if __name__ == '__main__':
  po = argparse.ArgumentParser(
    prog=sys.argv[ 0 ],
    description='Generate K-scheduler compatible CFG from fuzzuf CFG',
  );
  po.add_argument( 'filename', help='path to the instrumented executable binary' )
  po.add_argument( '-o', '--output', default='graph_data_pack', help='path to output K-scheduler compatible CFG' )
  po.add_argument( '-c', '--centricity', default='katz_cent', help='path to output Katz centricity' )
  po.add_argument( '-l', '--child', default='child_node', help='path to output child nodes' )
  po.add_argument( '-p', '--parent', default='parent_node', help='path to output parent nodes' )
  po.add_argument( '-b', '--border', default='border_edges', help='path to output border edges' )

  args = po.parse_args()

  sections = ''
  with subprocess.Popen([ 'objdump', '-h', args.filename ], stdout=subprocess.PIPE ) as list_sections:
    while list_sections.poll() is not None:
      (partial_stdout,partial_stderr) = list_sections.communicate()
      sections += partial_stdout.decode( 'utf-8' )
    (partial_stdout,partial_stderr) = list_sections.communicate()
    sections += partial_stdout.decode( 'utf-8' )
    if list_sections.returncode != 0:
      print( "Unable to enumerate sections in %s" % args.filename )
      sys.exit( list_sections.returncode )

  header = True
  skip_next = False
  for line in sections.splitlines():
    tokens = line.split()
    if skip_next:
      skip_next = False
    elif len( tokens ) != 0:
      if header:
        if tokens[ 0 ] == 'Idx':
          name_index = tokens.index( 'Name' )
          size_index = tokens.index( 'Size' )
          header = False
      else:
        if len( tokens ) > max( name_index, size_index ):
          section_name = tokens[ name_index ]
          section_size = int( tokens[ size_index ], 16 )
          if section_name.startswith( '.cfg-' ):
            break
        skip_next = True

  global_reverse_graph = defaultdict(list)
  global_graph = defaultdict(list)
  global_graph_weighted = defaultdict(dict)
  global_back_edge = list()

  with tempfile.NamedTemporaryFile() as temp:
    with subprocess.Popen([ 'objcopy', '-O', 'binary', '--only-section', section_name, args.filename, temp.name ] ) as dump_cfg:
      dump_cfg.wait()
      if dump_cfg.returncode != 0:
        print( "Unable to dump CFG from %s to %s" % ( args.filename, temp.name ) )
    for line in temp.read( section_size - 1 ).decode( 'utf-8' ).splitlines():
      tokens = line.split()
      from_id = int( tokens[ 0 ] )
      to_id = int( tokens[ 1 ] )
      if not from_id in global_graph:
        global_graph[ from_id ] = [ to_id ]
      else:
        if not to_id in global_graph[ from_id ]:
          global_graph[ from_id ].append( to_id )
      if not to_id in global_reverse_graph:
        global_reverse_graph[ to_id ] = [ from_id ]
      else:
        if not from_id in global_reverse_graph[ to_id ]:
          global_reverse_graph[ to_id ].append( from_id )
      if not from_id in global_graph_weighted:
        global_graph_weighted[ from_id ] = { to_id: 1 }
      else:
        if not to_id in global_graph_weighted[ from_id ]:
          global_graph_weighted[ from_id ][ to_id ] = 1
  unique_nodes = set()
  for k,v in global_graph.items():
    unique_nodes.add( k )
    for e in v:
      unique_nodes.add( e )
  for k,v in global_reverse_graph.items():
    unique_nodes.add( k )
  for k in unique_nodes:
    if not k in global_graph:
      global_graph[ k ] = []
    if not k in global_reverse_graph:
      global_reverse_graph[ k ] = []
    if not k in global_graph_weighted:
      global_graph_weighted[ k ] = {}

  back_edge,cnt = detect_back_edge(global_graph)
  if back_edge:
    for parent,child in back_edge:
      global_back_edge.append((parent, child))
      global_graph[parent].remove(child)
      del global_graph_weighted[parent][child]
      global_reverse_graph[child].remove(parent)
  
  graph_data_pack = [global_graph, global_reverse_graph, global_graph_weighted]
  pickle.dump(graph_data_pack, open( args.output, "wb"))

  # mapping discontinuous real node id into continuous tmp id for nk.graph modelling
  real_id_2_tmp_id = {}
  tmp_id_2_real_id = {}
  for idx, node in enumerate(sorted(global_graph_weighted.keys())):
    real_id_2_tmp_id[node] = idx
    tmp_id_2_real_id[idx] = node

  nk_new_graph = nk.Graph(n=len(global_graph_weighted), weighted=True, directed=True)
  for node, neis in global_graph_weighted.items():
    for nei, weight in neis.items():
      #nk_new_graph.addEdge( real_id_2_tmp_id[nei], real_id_2_tmp_id[node], w=( 0.5**(weight-1)))
      nk_new_graph.addEdge( real_id_2_tmp_id[nei], real_id_2_tmp_id[node], w=(1/weight))
  k = nk.centrality.KatzCentrality(nk_new_graph, alpha=0.5, beta=1.0, tol=1e-12)
  k.run()
  scaled_rank = {}
  max_score = max(k.scores())
  min_score = min(k.scores())
  for ele in k.ranking():
    real_id = tmp_id_2_real_id[ele[0]]

    if ele[1] == max_score:
      scaled_rank[real_id] = 10
    else:
      scaled_rank[real_id] = 10 / max_score * ele[1]

  with open( args.centricity, "w") as f:
    for key in sorted(scaled_rank.keys()):
      f.write(str(key+1) + " " + str(round(scaled_rank[key], 14)) + "\n")

  # add backedge to graph
  for parent, child in global_back_edge:
    global_graph[parent].append(child)
    global_reverse_graph[child].append(parent)

  with open( args.child, "w") as f:
    for key in sorted(global_graph.keys()):
      tmp = ' '.join([str(key+1)] + [str(ele+1) for ele in global_graph[key]]) + '\n'
      f.write(tmp)

  with open( args.parent, "w") as f:
    for key in sorted(global_reverse_graph.keys()):
      tmp = ' '.join([str(key+1)] + [str(ele+1) for ele in global_reverse_graph[key]]) + '\n'
      f.write(tmp)

  border_edges = []
  for node in sorted(global_graph.keys()):
    children = global_graph[node]
    children.sort()
    if len(children) > 1:
      for c in children:
        border_edges.append((node, c))
  with open( args.border, "w") as f:
    for p, c in border_edges:
      f.write(str(p+1) + " " + str(c+1) + "\n")

