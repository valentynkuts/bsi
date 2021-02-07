from analyse import *
from scan_sql_injection import scan_sql_injection
from scan_xss import scan_xss
url = 'http://localhost:65412'

webPen1(url)
req2(url)
webReq3(url)
auth4(url)
# scan_sql_injection(url)
scan_xss(url)