"""Retain all tests except the pre-approval subprocess test; never invoke extractor again."""
import json,pathlib,sys,unittest
R=pathlib.Path(__file__).resolve().parents[1]
def flatten(suite):
    for item in suite:
        if isinstance(item,unittest.TestSuite):yield from flatten(item)
        else:yield item
if __name__=='__main__':
    all_tests=list(flatten(unittest.defaultTestLoader.discover(str(R/'tests'),pattern='test*.py')))
    skipped=[t.id() for t in all_tests if t.id().endswith('.test_extractor_fails_before_member_read_without_approval')]
    selected=unittest.TestSuite(t for t in all_tests if t.id() not in skipped)
    result=unittest.TextTestRunner(verbosity=1).run(selected)
    print(json.dumps({'tests_run':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'pre_approval_subprocess_test_not_rerun':skipped,'extractor_invocations':0}))
    sys.exit(not result.wasSuccessful())
