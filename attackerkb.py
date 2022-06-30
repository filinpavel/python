import json
from attackerkb_api import AttackerKB

API_KEY = 'XXX'
api = AttackerKB(API_KEY)

listing = [
 CVE-2021-21972,
  CVE-2021-21973,
  CVE-2021-21974
]

for i in listing:
    print("Get a " + i)
    result = api.get_topics(name=i)
    print(json.dumps(result, indent=4, sort_keys=True))
