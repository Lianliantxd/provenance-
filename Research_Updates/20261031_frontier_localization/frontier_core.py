"""Unweighted context reachability; these are not native causal edges."""
import bisect
import collections


class ContextGraph:
    def __init__(self, events):
        self.events = events
        raw = collections.defaultdict(lambda: collections.defaultdict(list))
        for i, e in enumerate(events):
            for entity in {e['u'], e['v']}:
                raw[e['window'], entity][e['t']].append(i)
        self.timelines, self.memberships = {}, [[] for _ in events]
        for key, by_time in raw.items():
            times = sorted(by_time)
            groups = [by_time[t] for t in times]
            left, right = [], [0]*len(times)
            barrier = -1
            for j, group in enumerate(groups):
                left.append(barrier+1)
                if len(group)>1:
                    barrier=j
                for i in group:
                    self.memberships[i].append((key,j))
            barrier=len(times)
            for j in range(len(times)-1,-1,-1):
                right[j]=barrier-1
                if len(groups[j])>1:
                    barrier=j
            self.timelines[key]=(times,groups,left,right)

    def bounds(self, key, pos, k, gap_ns, unordered_ties):
        times, groups, left, right=self.timelines[key]
        if not unordered_ties and len(groups[pos])>1:
            return None
        lo, hi=0,len(times)-1
        if k is not None:
            lo=max(lo,pos-k);hi=min(hi,pos+k)
        if gap_ns is not None:
            lo=max(lo,bisect.bisect_left(times,times[pos]-gap_ns))
            hi=min(hi,bisect.bisect_right(times,times[pos]+gap_ns)-1)
        if not unordered_ties:
            lo=max(lo,left[pos]);hi=min(hi,right[pos])
        return lo,hi

    def distances(self, seeds, k=8, gap_ns=300_000_000_000, unordered_ties=False):
        """FIFO multi-source BFS with next-unseen interval enumeration.

        First discovery of a timeline group occurs at its minimum candidate
        distance, so all its events need only be enumerated once per channel.
        Outgoing relations still use each source's original, complete timeline.
        """
        nxt={key:list(range(len(t[0])+1)) for key,t in self.timelines.items()}

        def find(parent,j):
            while parent[j]!=j:
                parent[j]=parent[parent[j]];j=parent[j]
            return j

        distance=[-1]*len(self.events)
        parent=[None]*len(self.events)
        queue=collections.deque(sorted(set(seeds)))
        for i in queue:
            distance[i]=0
        groups_enumerated=0
        while queue:
            i=queue.popleft()
            for key,pos in self.memberships[i]:
                bounds=self.bounds(key,pos,k,gap_ns,unordered_ties)
                if bounds is None:
                    continue
                lo,hi=bounds
                link=nxt[key]
                j=find(link,lo)
                while j<=hi:
                    groups_enumerated+=1
                    for target in self.timelines[key][1][j]:
                        if distance[target]<0:
                            distance[target]=distance[i]+1
                            parent[target]=(i,key[1])
                            queue.append(target)
                    link[j]=find(link,j+1)
                    j=find(link,j)
        return distance,parent,groups_enumerated


def relaxations(mask):
    return {'neighbor_group_limit':None if mask&1 else 8,
            'max_gap_ns':None if mask&2 else 300_000_000_000,
            'unordered_ties':bool(mask&4),
            'max_event_hops':None if mask&8 else 3}


def mask_names(mask):
    return [name for bit,name in [(1,'NEIGHBOR_GROUP_LIMIT'),(2,'TIME_GAP'),
            (4,'UNORDERED_TIE_CONTEXT'),(8,'HOP_LIMIT')] if mask&bit]


def minimal_success_masks(success):
    return sorted(m for m in success if not any(other!=m and other&m==other for other in success))
