import requests
from contextlib import closing
from urllib.error import URLError, HTTPError
url = 'https://devbuilds.s.kaspersky-labs.com/kvrt_linux/latest/kvrt.run'
try:
    with closing(requests.get(url, stream=True)) as r:
        
        if r.status_code == 200:
            
            with open('kvrt.run', 'wb') as f:
                
                for chunk in r.iter_content(chunk_size=8192):
                    if chunk:  
                        f.write(chunk)
        else:
            print(f"Ошибка при скачивании файла: код статуса {r.status_code}")
except (URLError, HTTPError) as e:
    print(f"Произошла ошибка при скачивании файла: {e.reason}")
