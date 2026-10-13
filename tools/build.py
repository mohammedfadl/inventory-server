#!/usr/bin/env python3
"""يحوّل ملف النظام (inventory-system.html) إلى نسخة الخادم:
   python3 tools/build.py /path/to/inventory-system.html
ينتج: public/index.html  و  permissions.json  (يُقرأ من النظام نفسه فيبقى متوافقًا مع كل تطوير)."""
import re, json, sys, os
root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
src = sys.argv[1] if len(sys.argv) > 1 else os.path.join(root, 'inventory-system.html')
s = open(src, encoding='utf-8').read()

tail = 'boot();\n</script>\n</body>'
assert s.count(tail) == 1, 'لم يُعثر على نهاية النظام المتوقعة'
s = s.replace(tail, '</script>\n<script src="/server-adapter.js"></script>\n</body>')

cdn = 'https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js'
vend = os.path.join(root, 'vendor', 'xlsx.full.min.js')
if os.path.exists(vend):                       # نسخة محلية من مكتبة Excel (للشبكات المغلقة)
    s = s.replace(cdn, '/xlsx.full.min.js')
    open(os.path.join(root, 'public', 'xlsx.full.min.js'), 'wb').write(open(vend, 'rb').read())

m = re.search(r'const STORE_OWNER_TABS = (\{.*?\});', s, re.S); assert m
owner = json.loads(re.sub(r'(\w+):', r'"\1":', m.group(1).replace("'", '"')))
stores = re.search(r"const STORES = (\[.*?\]);", s).group(1)
stores = [x for x in json.loads(stores.replace("'", '"')) if x != 'users']
tabs = re.findall(r"\{id:'(\w+)', label:", s[s.index('const TABS = ['):s.index('];', s.index('const TABS = ['))])
tabs = [t for t in tabs if t != 'users']
open(os.path.join(root, 'public', 'index.html'), 'w', encoding='utf-8').write(s)
json.dump({'stores': stores, 'backupStores': stores, 'tabs': tabs, 'storeOwnerTabs': owner},
          open(os.path.join(root, 'permissions.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
print('built:', len(s), 'bytes;', len(stores), 'stores;', len(tabs), 'tabs')
