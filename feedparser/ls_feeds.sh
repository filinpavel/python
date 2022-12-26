 cat feeds.opml | python3 -c 'import re,sys; [ print(m.group(1)) for ''ln in sys.stdin for m in [ re.search("(?i)xmlUrl=\"(.*?)\"", ln) ] ''if m is not None ]'
