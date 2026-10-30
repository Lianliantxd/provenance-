import unittest
import numpy as np
from retrieval_experiment import Neighborhood,OperationStats,transition_matrix,diffuse,decode,canonical_key


def event(key,t,u=1,v=2,op='EVENT_READ'):
    return dict(key=key,t=t,u=u,v=v,op=op,window='w')


class RetrievalTests(unittest.TestCase):
    def test_shared_AB_fact_has_same_priority_despite_storage_identity(self):
        a=event('native|100|EVENT_READ',100)
        b=dict(a,key='dbrow:100000',native_uuid='native')
        self.assertEqual(canonical_key(a),canonical_key(b))
    def test_ties_are_barriers_not_deleted(self):
        es=[event('a',0),event('b',10),event('c',10),event('d',20)]
        n=Neighborhood(es)
        self.assertEqual(n.neighbors(0),[])
        self.assertEqual(n.neighbors(3),[])

    def test_truncation_does_not_invent_adjacency_or_renormalize(self):
        es=[event('a',0),event('b',10),event('c',20)]
        n=Neighborhood(es)
        full=n.neighbors(0)
        retained=[x for x in full if x[0]==2]
        self.assertLess(sum(x[2] for x in retained),sum(x[2] for x in full))

    def test_shuffle_preserves_every_state_row_mass(self):
        es=[event('a',0,1,2),event('b',20,1,3,'EVENT_WRITE'),event('c',40,2,3)]
        n=Neighborhood(es)
        links=[(i,j,x,w) for i in range(3) for j,x,w in n.neighbors(i)]
        s=OperationStats({1:'subject',2:'file',3:'file'});s.update(es)
        a=transition_matrix(es,links,s,True,True)
        b=transition_matrix(es,links,s,True,True,shuffle_seed=3)
        np.testing.assert_allclose(np.asarray(a.sum(axis=1)),np.asarray(b.sum(axis=1)),atol=1e-12)

    def test_dangling_states_return_mass_to_seed(self):
        from scipy.sparse import csr_matrix
        matrix=csr_matrix((3,3))
        values,report=diffuse(matrix,np.array([1.,0.,0.]),.2)
        np.testing.assert_allclose(values,[1.])
        self.assertTrue(report['converged'])
        self.assertAlmostEqual(report['visitation_weighted_restart'],1.)

    def test_node_budget_includes_all_query_nodes(self):
        es=[event('a',0,1,3)]
        q=[{'index':1},{'index':2}]
        out=decode(es,[1.],q,2,500)
        self.assertEqual(out['nodes'],[1,2]);self.assertEqual(out['events'],[])
        self.assertEqual(decode(es,[1.],q,1,500)['status'],'INFEASIBLE_Q_EXCEEDS_NODE_BUDGET')

    def test_unknown_operation_statistics_do_not_assert_certainty(self):
        stats=OperationStats({1:'subject',2:'file'})
        self.assertAlmostEqual(stats.gate(event('a',0),event('b',1),1),.55)


if __name__=='__main__':unittest.main()
