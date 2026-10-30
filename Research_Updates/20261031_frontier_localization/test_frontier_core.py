"""Compare optimized traversal with explicit relation enumeration on small graphs."""
import collections
import random
import unittest
from frontier_core import ContextGraph, minimal_success_masks


def explicit(events,seeds,k,gap,ties):
    raw=collections.defaultdict(lambda:collections.defaultdict(list))
    for i,e in enumerate(events):
        for x in {e['u'],e['v']}:
            raw[e['window'],x][e['t']].append(i)
    adjacency=[set() for _ in events]
    for by_time in raw.values():
        ts=sorted(by_time)
        for p,t in enumerate(ts):
            if not ties and len(by_time[t])>1:
                continue
            for i in by_time[t]:
                if ties:
                    adjacency[i].update(set(by_time[t])-{i})
                for direction in [-1,1]:
                    j=p+direction;steps=0
                    while 0<=j<len(ts) and (k is None or steps<k):
                        if gap is not None and abs(ts[j]-t)>gap:
                            break
                        if not ties and len(by_time[ts[j]])>1:
                            break
                        adjacency[i].update(by_time[ts[j]])
                        steps+=1;j+=direction
    d=[-1]*len(events);q=collections.deque(sorted(seeds))
    for i in seeds:d[i]=0
    while q:
        i=q.popleft()
        for j in adjacency[i]:
            if d[j]<0:d[j]=d[i]+1;q.append(j)
    return d


class TestFrontier(unittest.TestCase):
    def test_tie_barrier_is_not_a_total_order(self):
        es=[{'u':0,'v':i+1,'t':t,'window':'w'} for i,t in enumerate([0,1,1,2])]
        g=ContextGraph(es)
        self.assertEqual(g.distances({0},k=8,gap_ns=None)[0],[0,-1,-1,-1])
        self.assertEqual(g.distances({0},k=8,gap_ns=None,unordered_ties=True)[0],[0,1,1,1])

    def test_gap_boundary_and_hops(self):
        es=[{'u':0,'v':i+1,'t':t,'window':'w'} for i,t in enumerate([0,300,601])]
        g=ContextGraph(es)
        self.assertEqual(g.distances({0},k=1,gap_ns=300)[0],[0,1,-1])
        self.assertEqual(g.distances({0},k=1,gap_ns=None)[0],[0,1,2])

    def test_window_separation(self):
        es=[{'u':0,'v':1,'t':0,'window':'a'},{'u':0,'v':2,'t':1,'window':'b'}]
        self.assertEqual(ContextGraph(es).distances({0},k=None,gap_ns=None,unordered_ties=True)[0],[0,-1])

    def test_eight_group_limit_changes_shortest_hops(self):
        es=[{'u':0,'v':i+1,'t':i,'window':'w'} for i in range(21)]
        graph=ContextGraph(es)
        self.assertEqual(graph.distances({0},k=8,gap_ns=None)[0][9],2)
        self.assertEqual(graph.distances({0},k=None,gap_ns=None)[0][9],1)

    def test_all_minimal_alternatives_retained(self):
        self.assertEqual(minimal_success_masks({1,2,3,5,6,7,8,9,10,11}),[1,2,8])

    def test_exhaustive_small_random_graph_comparison(self):
        rng=random.Random(4)
        for case in range(30):
            es=[{'u':rng.randrange(5),'v':rng.randrange(5),
                 't':rng.randrange(12)*100_000_000_000,'window':str(rng.randrange(2))}
                for _ in range(rng.randrange(10,41))]
            seeds=set(rng.sample(range(len(es)),3));g=ContextGraph(es)
            for k in [8,None]:
                for gap in [300_000_000_000,None]:
                    for ties in [False,True]:
                        with self.subTest(case=case,k=k,gap=gap,ties=ties):
                            self.assertEqual(g.distances(seeds,k,gap,ties)[0],explicit(es,seeds,k,gap,ties))


if __name__=='__main__':unittest.main()
