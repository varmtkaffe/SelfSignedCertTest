#!/usr/bin/env python3
'''
Generate a self-signed certificate
Note: this is typically not done with python, instead a command line utility is
used, such as mkcert or openssl. Example:
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 \
        -noenc -subj '/CN=Mel/O=Lexikon/'
To run the Django server with TLS support, I have installed django-sslserver and
added it to RestWeb/settings.py
'''
from OpenSSL import crypto


if __name__ == '__main__':
    '''
    Generate an RSA key pair (public and private key)
    The private key is what is used to sign your certificate, why this is
    referred to a self-signed certificate.
    For a trusted certificate (signed by a known Certificate Authority) one
    needs to create a CSR (Certificate Signing Request) and through some sort
    of protocol (typically ACME) prove identity, and get a sign certificate
    back from e.g. Let's encrypt. This is out of scope for this challenge, and
    involves other stuff than python.
    '''
    key_pair = crypto.PKey()
    key_pair.generate_key(crypto.TYPE_RSA, 4096)

    '''
    Generate a X509 certificate to the Common Name "Melinda" and Organization
    "Lexikon"
    '''
    valid_not_before = 0
    valid_not_after = 10*365*24*60*60
    cert = crypto.X509()
    cert.get_subject().CN = "Melinda"
    cert.get_subject().O = "Lexikon"
    cert.gmtime_adj_notBefore(valid_not_before)
    cert.gmtime_adj_notAfter(valid_not_after)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key_pair)
    cert.sign(key_pair, 'sha512')   # Signed by our own key

    '''
    Write certificate and private key to disk
    '''
    with open("cert.pem", "wt") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))

    with open("key.pem", "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key_pair).decode("utf-8"))