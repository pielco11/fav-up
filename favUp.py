import sys
import requests
import base64

import mmh3
from ipwhois import IPWhois
from bs4 import BeautifulSoup
from shodan import Shodan

shodan = Shodan(open("SHODAN_API.txt", "r").readline().strip())

def faviconHash(data, source):
    if source == "web":
        b64data = base64.encodebytes(data).decode()
    else:
        b64data = base64.encodebytes(data)
    return mmh3.hash(b64data)

def searchFaviconHTML(link):
    data = requests.get(link, stream=True)
    soup = BeautifulSoup(data.content, 'html.parser')
    iconLink = soup.find('link', rel='icon').get("href")
    if not iconLink.startswith("http"):
        iconLink = link + "/" + iconLink
    return requests.get(iconLink)

def shodanSearch(favhash):
    results = shodan.search(f"http.favicon.hash:{favhash}")
    for s in results["matches"]:
        print(f"Real-IP: {s['ip_str']}")

def deepConnectionLens(response):
    mIP = list(response.raw._connection.sock.getpeername())[0]
    print(f"Mask-IP: {mIP}")
    print(f"Mask-ISP: {IPWhois(mIP).lookup_whois()['nets'][0]['name']}")

if __name__ == '__main__':
    source = "file"
    if sys.argv[1] == "--favicon-file":
        data = open(sys.argv[2], 'rb').read()
    elif sys.argv[1] == "--favicon-url" or "--web":
        source = "web"
        data = requests.get(sys.argv[2], stream=True)
        deepConnectionLens(data)
        if sys.argv[1] == "--web":
            data = searchFaviconHTML(sys.argv[2]).content
        else:
            data = data.content
    favhash = faviconHash(data, source)
    print(f"Favicon Hash: {favhash}")
    shodanSearch(favhash)

