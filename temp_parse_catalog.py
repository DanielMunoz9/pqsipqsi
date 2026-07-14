import json
from collections import defaultdict
path = r'C:\Users\Daniel\AppData\Roaming\Code\User\workspaceStorage\57e1918cf789ee64326758318f9b5079\GitHub.copilot-chat\chat-session-resources\fb4562a5-c1fd-4f38-902e-2c5a0cec0d65\call_fdXHhvmFAHhTnw2VXlXjOMFG__vscode-1783474621885\content.txt'
with open(path, encoding='utf-8') as f:
    text = f.read()
rows = json.loads(text[text.find('['):])
by_type = defaultdict(list)
def normalize(v):
    return (v or '').strip().lower()
for r in rows:
    st = normalize(r.get('special_type'))
    if st in ('iconico', 'extra', 'diamante'):
        by_type[st].append((r.get('display_name'), r.get('player_pseudo')))
print('total rows', len(rows))
for t in ('iconico', 'extra', 'diamante'):
    print('---', t, len(by_type[t]))
    for name, pseudo in by_type[t]:
        print(f'{t}: {name} / {pseudo}')
