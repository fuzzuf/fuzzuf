import sys
import ipdb
import glob
import time
import os
from os import path
import pickle
import networkit as nk
from collections import defaultdict

if __name__ == '__main__':

    covered_node = []
    # load global_graph, global_reverse_graph, global_graph_weighted
    global_graph, global_reverse_graph, global_graph_weighted = pickle.load(open("graph_data_pack", "rb"))

    while True:
        time.sleep(5)
        signal = None
        if not path.exists("signal"):
            continue
        with open("signal", "r") as f: signal = f.read()
        if signal == "1\n":
            covered_node.clear()
            with open("cur_coverage", "r") as f:
                # AFL instrumention ID starts with 1, we shift them by 1 and make them starti from 0
                covered_node = [int(ele)-1 for ele in f.read().split() if ele != '']

            # delete covered node
            for node in covered_node:
                if node not in global_graph: continue
                children, parents = global_graph[node], global_reverse_graph[node]
                # link prior and next node
                for child in children:
                    for parent in parents:
                        if child not in global_graph[parent]:
                            global_graph[parent].append(child)
                            global_graph_weighted[parent][child] = global_graph_weighted[parent][node] + global_graph_weighted[node][child]
                        if parent not in global_reverse_graph[child]:
                            global_reverse_graph[child].append(parent)

                # del current node
                del global_graph[node]
                del global_reverse_graph[node]
                del global_graph_weighted[node]

                # del link to parent
                for parent in parents:
                    global_graph[parent].remove(node)
                    # del edge globally
                    del global_graph_weighted[parent][node]
                # del link to child
                for child in children:
                    global_reverse_graph[child].remove(node)

            # mapping discontinuous real node id into continuous tmp id for nk.graph modelling
            real_id_2_tmp_id = {}
            tmp_id_2_real_id = {}
            for idx, node in enumerate(sorted(global_graph_weighted.keys())):
                real_id_2_tmp_id[node] = idx
                tmp_id_2_real_id[idx] = node

            nk_new_graph = nk.Graph(n=len(global_graph_weighted), weighted=True, directed=True)
            for node, neis in global_graph_weighted.items():
                for nei, weight in neis.items():
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

            with open("dyn_katz_cent", "w") as f:
                for key in sorted(scaled_rank.keys()):
                    # shift graph node id by 1 and convert them into AFL instrumentation ID
                    f.write(str(key+1) + " " + str(round(scaled_rank[key], 14)) + "\n")

            with open("signal", "w") as f: f.write("0\n")

            print("covered " + str(len(covered_node)) + " node, generate new graph." )

