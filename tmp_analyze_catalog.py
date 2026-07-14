import json, collections
path = r'C:\Users\Daniel\AppData\Roaming\Code\User\workspaceStorage\57e1918cf789ee64326758318f9b5079\GitHub.copilot-chat\chat-session-resources\fb4562a5-c1fd-4f38-902e-2c5a0cec0d65\call_fdXHhvmFAHhTnw2VXlXjOMFG__vscode-1783474621885\content.txt'
text = open(path, encoding='utf-8').read()
start = text.find('[')
rows = json.loads(text[start:])

def normalize(v):
    return (v or '').strip().lower()

def pool_for(row):
    st = normalize(row.get('special_type'))
    if st in {'iconico','extra','diamante'}:
        return st
    if normalize(row.get('variant')) == 'dorado':
        return 'legendario_dorado'
    rarity = normalize(row.get('rarity'))
    return rarity or 'comun'

counts = collections.Counter(pool_for(r) for r in rows)
print('total', len(rows))
for k in ['comun','raro','epico','legendario','legendario_dorado','iconico','extra','diamante']:
    print(k, counts.get(k,0))
print('special_non_normal', sum(1 for r in rows if normalize(r.get('special_type')) not in {'','normal'}))
print('gold_variant_without_special', sum(1 for r in rows if normalize(r.get('variant'))=='dorado' and normalize(r.get('special_type'))=='normal'))
print('special_type_values', sorted({normalize(r.get('special_type')) for r in rows}))
print('variant_values', sorted({normalize(r.get('variant')) for r in rows}))
print('rarity_values', sorted({normalize(r.get('rarity')) for r in rows}))
for r in rows:
    st = normalize(r.get('special_type'))
    if st not in {'','normal','iconico','extra','diamante'}:
        print('unexpected_special', st, r['id'], r.get('display_name'))
