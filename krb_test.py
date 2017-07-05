import requests
import kerberos
import logging

class KerberosTicket:
    def __init__(self, service):
        __, krb_context = kerberos.authGSSClientInit(service)
        kerberos.authGSSClientStep(krb_context, "")
        self._krb_context = krb_context
        self.auth_header = ("Negotiate " +
                            kerberos.authGSSClientResponse(krb_context))
                            
    def verify_response(self, auth_header):
        # Handle comma-separated lists of authentication fields
        for field in auth_header.split(","):
            kind, __, details = field.strip().partition(" ")
            if kind.lower() == "negotiate":
                auth_details = details.strip()
                break
        else:
            raise ValueError("Negotiate not found in %s" % auth_header)
        # Finish the Kerberos handshake
        krb_context = self._krb_context
        if krb_context is None:
            raise RuntimeError("Ticket already used for verification")
        self._krb_context = None
        kerberos.authGSSClientStep(krb_context, auth_details)
        kerberos.authGSSClientClean(krb_context)


def proxy_auth(response):
    auth_fields = {}
    for field in response.headers.get("proxy-authenticate", "").split(","):
        kind, __, details = field.strip().partition(" ")
        auth_fields[kind.lower()] = details.strip()
    return auth_fields

def www_auth(response):
    auth_fields = {}
    for field in response.headers.get("www-authenticate", "").split(","):
        kind, __, details = field.strip().partition(" ")
        auth_fields[kind.lower()] = details.strip()
    return auth_fields

krb = KerberosTicket("HTTP@<fqdn>")
headers = {"Authorization": krb.auth_header}
print headers
r = requests.get("http://<fqdn>/some/URI", headers=headers)
print r.status_code
krb.verify_response(r.headers["www-authenticate"])

#r = requests.get("http://<fqdn>")
#print r.status_code
#print r.headers["www-authenticate"]
#print www_auth(r)

# Testing
#r = requests.get("http://<fqdn>/ip.php")
#print "http://<fqdn>/ip.php KRB:" 
#print r.status_code == 401 and www_auth(r).get('negotiate') == ''
#r = requests.get("http://<fqdn>/some/URI")
#print "http://<fqdn>/some/ KRB:"
#print r.status_code == 401 and www_auth(r).get('negotiate') == ''

#__, krb_context = kerberos.authGSSClientInit("HTTP@<fqdn>")
#kerberos.authGSSClientStep(krb_context, "")
#negotiate_details = kerberos.authGSSClientResponse(krb_context)
#headers = {"Authorization": "Negotiate " + negotiate_details}
#r = requests.get("http://<fqdn>/some/URI", headers=headers)
#print r.status_code
#print r

