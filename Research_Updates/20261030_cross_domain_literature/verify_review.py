import collections
import csv
import hashlib
import json
import re
from pathlib import Path

p = Path(__file__).resolve().parent
rows = list(csv.DictReader((p / 'PAPER_INVENTORY.csv').open(encoding='utf-8', newline='')))
m = json.loads((p / 'MANIFEST.json').read_text(encoding='utf-8'))
report = (p / 'REVIEW_53_PAPERS.md').read_text(encoding='utf-8')
checks = {
    'count_53': len(rows) == m['paper_count'] == 53,
    'groups': dict(collections.Counter(r['id'][0] for r in rows)) == m['groups'],
    'unique_ids_titles_urls': all(len({r[k].casefold() for r in rows}) == 53 for k in ('id', 'title', 'url')),
    'all_have_task_method_limit_and_source': all(all(r[k] for k in ('input_output', 'method', 'limitation', 'relevance', 'venue', 'url')) for r in rows),
    'all_linked_in_report': all(report.count('](' + r['url'] + ')') == 1 for r in rows),
    'publication_years_in_window': all(bool(re.search(r'202[3-6]', r['venue'])) for r in rows),
    'manifest_hashes': all(hashlib.sha256((p / name).read_bytes()).hexdigest() == digest for name, digest in m['files'].items()),
}
print(json.dumps({'checks': checks, 'pass': all(checks.values()), 'limitation': '验证交付文件的一致性，不核验网页内容、论文质量或科研结论'}, ensure_ascii=False, indent=2))
raise SystemExit(0 if all(checks.values()) else 1)
