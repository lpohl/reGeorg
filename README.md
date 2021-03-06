reGeorg
=========

```                    _____
  _____   ______  __|___  |__  ______  _____  _____   ______
 |     | |   ___||   ___|    ||   ___|/     \|     | |   ___|
 |     \ |   ___||   |  |    ||   ___||     ||     \ |   |  |
 |__|\__\|______||______|  __||______|\_____/|__|\__\|______|
                    |_____|
                    ... every office needs a tool like Georg
```
willem@sensepost.com / [@\_w\_m\_\_]

sam@sensepost.com / [@trowalts]

etienne@sensepost.com / [@kamp_staaldraad]


Version
----

1.0a (modifyed by lpohl)

Dependencies
-----------

reGeorg requires Python 2.7 and the following modules:

* [urllib3] - HTTP library with thread-safe connection pooling, file post, and more.
* [kerberos] - KRB5 Library for Negotiate Authentication against a Proxy
* python > 2.7.5? I had strange problems with the default python (2.7.4) on Kali Linux so I used pyenv and python 2.7.10

Usage
--------------

```
$ reGeorgSocksProxy.py [-h] [-l] [-p] [-r] -u  [-v] [-X] [-A] [-a]

Socks server for reGeorg HTTP(s) tunneller

optional arguments:
  -h, --help           show this help message and exit
  -l , --listen-on     The default listening address
  -p , --listen-port   The default listening port
  -r , --read-buff     Local read buffer, max data to be sent per POST
  -u , --url           The url containing the tunnel script
  -v , --verbose       Verbose output[INFO|DEBUG]
  -X , --proxy         Set Proxy URL (http://myproxy:8080)
  -A , --authproxy     Use Kerberos Auth with the Proxy
  -a , --auth          Use Basic Auth for tunnel Script Access ( -a user:pass)

```

* **Step 1.**
Upload tunnel.(aspx|ashx|jsp|php) to a webserver (How you do that is up to
you)

* **Step 2.**
Configure you tools to use a socks proxy, use the ip address and port you
specified when
you started the reGeorgSocksProxy.py

** Note, if you tools, such as NMap doesn't support socks proxies, use
[proxychains] (see wiki) 

* **Step 3.** Hack the planet :)


Example
---------
```
Direct HTTP Access to Uploaded Script
$ python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp

Access over Proxy + KRB Auth to HTTPS and Basic Auth Protected tunnel script
$ python reGeorgSocksProxy.py -u https://upload.sensepost.net/tunnel/tunnel.jsp -x http://proxy.sensepost.net:8080 -A -a user:pass
```

License
----

MIT


[@\_w\_m\_\_]:http://twitter.com/_w_m__
[@trowalts]:http://twitter.com/trowalts
[@kamp_staaldraad]:http://twitter.com/kamp_staaldraad
[urllib3]:https://pypi.python.org/pypi/urllib3
[kerberos]:https://pypi.python.org/pypi/kerberos
[proxychains]:http://sourceforge.net/projects/proxychains/
