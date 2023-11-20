import sys
from cryptography import x509
from datetime import datetime
import os
import fnmatch
from pathlib import Path

def certvalid(cert):
    now = datetime.now()
    if now > cert.not_valid_before and now < cert.not_valid_after:
        return True
    else:
        return False
    
if __name__ == '__main__':
    if len(sys.argv) != 1:
        print(f'Usage: {sys.argv[0]} <anchors path>')
        exit(1)

    objs = os.scandir('/etc/ssl/certs')
    certdict = {}

    for o in objs:
        if fnmatch.fnmatch(o.name, '*.*'):
            abscertname = os.getcwd() / Path('/etc/ssl/certs') / o.name
            with open(abscertname, 'rb') as fctr:
                cert = x509.load_pem_x509_certificate(fctr.read())
                if certvalid(cert):
                    certdict[cert.subject] = cert

    for k, v in certdict.items():
        print(f'K: {k} ========> V: {v}')