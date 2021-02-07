"""
Modified example coming from:
Python Web Penetration Testing Cookbook.pdf

"""

import requests
from requests.auth import HTTPBasicAuth


# http://localhost:65412

def webPen1(url):
    verbs = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'TRACE', 'TEST']
    for verb in verbs:
        req = requests.request(verb, url)
        print(verb, req.status_code, req.reason)
        if verb == 'TRACE' and 'TRACE / HTTP/1.1' in req.text:
            print('Possible Cross Site Tracing vulnerability found')


def req2(url):
    req = requests.get(url)
    headers = ['Server', 'Date', 'Via', 'X-Powered-By', 'X-Country-Code']
    for header in headers:
        try:
            result = req.headers[header]
            print('%s: %s' % (header, result))
        except Exception as error:
            print('%s: Not found' % header)


def webReq3(url):
    url = url.strip()
    req = requests.get(url)
    print(url, 'report:')
    try:
        xssprotect = req.headers['X-XSS-Protection']
        if xssprotect != '1; mode=block':
            print('X-XSS-Protection not set properly, XSS may be possible:', xssprotect)
    except:
        print('X-XSS-Protection not set, XSS may be possible')
    try:
        contenttype = req.headers['X-Content-Type-Options']
        if contenttype != 'nosniff':
            print('X-Content-Type-Options not set properly:', contenttype)
    except:
        print('X-Content-Type-Options not set')
    try:
        hsts = req.headers['Strict-Transport-Security']
    except:
        print('HSTS header not set, MITM attacks may be possible')
    try:
        csp = req.headers['Content-Security-Policy']
        print('Content-Security-Policy set:', csp)
    except:
        print('Content-Security-Policy missing')


def auth4(url):
    with open('passwords.txt') as passwords:
        for password in passwords.readlines():
            password = password.strip()
            req = requests.get(url, auth=HTTPBasicAuth('admin', password))
            if req.status_code == 401:
                print(password, 'failed.')
            elif req.status_code == 200:
                print('Login successful, password:', password)
                break
            else:
                print('Error occurred with', password)
                break
