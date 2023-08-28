#!/usr/bin/env python3

import requests
import base64
import argparse
import time
import json
import os

import mmh3
from tqdm import tqdm
from ipwhois import IPWhois
from bs4 import BeautifulSoup
from shodan import Shodan
from shodan.cli.helpers import get_api_key
from fake_useragent import UserAgent
from fake_useragent.errors import FakeUserAgentError

class FavUp(object):
    def __init__(self, *args, **kwargs):
        """ Parse the arguments
        """

        self.FALLBACK_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
        self.show = None
        self._iterator = None
        self.shodan = None

        self.key = None
        self.keyFile = None
        self.shodanCLI = None

        self.faviconFile = []
        self.faviconURL = []
        self.web = []

        self.fileList = []
        self.urlList = []
        self.webList = []

        self.faviconsList = []

        self.current_work_dir = os.getcwd()
        self.ua = UserAgent(fallback=self.FALLBACK_UA)

        self.output = ""
        self._output = None

        if kwargs.get('show'):
            self.show = True
            ap = argparse.ArgumentParser(prog="favup", usage="python3 %(prog)s [options]")

            ap.add_argument('-kf', '--key-file', help="Specify the file which contains the API key.")
            ap.add_argument('-k', '--key', help="Specify the API key.")
            ap.add_argument('-sc', '--shodan-cli', help="Load the API key from Shodan CLI.", action="store_true")

            ap.add_argument('-ff', '--favicon-file', help="Load the favicon icon from a local file.")
            ap.add_argument('-fu', '--favicon-url', help="Load the favicon icon from an URL.")
            ap.add_argument('-w', '--web', help="Extracts the favicon location from the page.")
            ap.add_argument('-fh', '--favicon-hash', help='Running from direct favicon hash number')

            ap.add_argument('-fl', '--favicon-list',
                help="Iterate over a file that contains the full path of all the icons which you want to lookup.")
            ap.add_argument('-ul', '--url-list',
                help="Iterate over a file that contains the full URL of all the icons which you want to lookup.")
            ap.add_argument('-wl', '--web-list',
                help="Iterate over a file that contains all the domains which you want to lookup.")
            
            ap.add_argument('-o', '--output', help="Specify output file, currently supported formats are CSV and JSON.")


            args = self._argsCheck(ap.parse_args())
            self.key = args.key
            self.keyFile = args.key_file
            self.shodanCLI   = args.shodan_cli
            self.faviconFile = [args.favicon_file] if args.favicon_file else []
            self.faviconURL  = [args.favicon_url] if args.favicon_url else []
            self.faviconHashVal = [args.favicon_hash] if args.favicon_hash else []
            self.web = [args.web] if args.web else []
            self.fileList = self._serializeListFile(args.favicon_list) if args.favicon_list else []
            self.urlList = self._serializeListFile(args.url_list) if args.url_list else []
            self.webList = self._serializeListFile(args.web_list) if args.web_list else []
            self.output = args.output

            self._iterator = tqdm(total=len(self.fileList)+len(self.urlList)+len(self.webList))

            if self.output:
                self._output = {
                    'type': self.output.split('.')[1],
                    'file': open(self.output, 'w')
                }

            self.run()

            if self.output:
                self._output['file'].close()

    
    def _argsCheck(self, args):
        if not (args.key_file or args.key or args.shodan_cli):
            print('[x] Please specify the key with --key, --key-file or --shodan-cli.')
            exit(1)

        if not (args.favicon_file or args.favicon_url or args.web or
                args.favicon_list or args.url_list or args.web_list or args.favicon_hash):
            print('[x] Please specify the source of the favicon with --favicon-file, --favicon-url, --favicon-hash, --web'+
                ', --favicon-list, --url-list or --web-list.')
            exit(1)

        return args
    
    def _serializeListFile(self, inputFile):
        """ Remove whitespace chars and lines
        """
        _output = []
        with open(inputFile, 'r') as inFile:
            for _l in inFile:
                if _l.strip():
                    _output.append(_l.strip())
        return _output

    def run(self):
        if self.keyFile:
            self.shodan = Shodan(open(self.keyFile, "r").readline().strip())
        elif self.key:
            self.shodan = Shodan(self.key)
        elif self.shodanCLI:
            self.shodan = Shodan(get_api_key())
        else:
            print('[x] Wrong input API key type.')
            exit(1)
        
        if self.faviconHashVal:
            self._iterator.set_description(f"[+] Using Favicon Hash as parameter")
            self._iterator.update(1)
            for fav in self.faviconHashVal:    
                _fH = fav
                self.faviconsList.append({
                    'favhash': _fH,
                    '_origin': self.faviconHashVal
                })

        if self.faviconFile or self.fileList:
            self.fileList.extend(self.faviconFile)
            for fav in self.fileList:
                self._iterator.set_description(f"[+] iterating over favicon files | processing {fav}")
                self._iterator.update(1)
                data = open(fav, 'rb').read()
                _fH = self.faviconHash(data)
                self.faviconsList.append({
                    'favhash': _fH,
                    'file': fav,
                    '_origin': fav
                    })
        if self.faviconURL or self.urlList:
            self.urlList.extend(self.faviconURL)
            for fav in self.urlList:
                self._iterator.set_description(f"[+] iterating over favicon URLs | processing {fav}")
                self._iterator.update(1)
                headers = {
                        'User-Agent': self.get_user_agent(),
                    }
                data = requests.get(fav, stream=True, headers=headers, verify=False)
                _dcL = self.deepConnectionLens(data)
                data = data.content
                _fH = self.faviconHash(data)
                self.faviconsList.append({
                    'favhash': _fH,
                    'url': self.faviconURL,
                    'domain': fav,
                    'maskIP': _dcL['mIP'],
                    'maskISP': _dcL['mISP'],
                    '_origin': fav
                    })
        if self.web or self.webList:
            self.webList.extend(self.web)
            for w in self.webList:
                self._iterator.set_description(f"[+] iterating over domains | processing {w}")
                self._iterator.update(1)
                try:
                    headers = {
                        'User-Agent': self.get_user_agent(),
                    }
                    data = requests.get(f"https://{w}", stream=True, headers=headers, verify=False)
                    _dcL = self.deepConnectionLens(data)
                    data = self.searchFaviconHTML(f"https://{w}")
                    if not isinstance(data, str):    
                        _fH = self.faviconHash(data.content, web_source=True)
                    else:
                        _fH = "not-found"
                except requests.exceptions.ConnectionError:
                    self._iterator.write(f"[x] Connection refused by {w}.")
                    if len(self.webList) == 1:
                        exit(1)
                self.faviconsList.append({
                    'favhash': _fH,
                    'domain': f"https://{w}",
                    'maskIP': _dcL['mIP'],
                    'maskISP': _dcL['mISP'],
                    '_origin': w
                    })
        _alreadyScanned = {}

        _aF = set([f for i in self.faviconsList for f in i])
        _aF.remove('_origin')
        _aF.add('found_ips')

        _cObj = {}
        for f in _aF:
            _cObj.update({f:''})

        if self.output:
            if self._output['type'].lower() == 'csv':
                self._output['file'].write(','.join(f for f in _aF)+'\n')

        self._iterator.reset(total=len(self.faviconsList))
        for _fObject in self.faviconsList:
            self._iterator.set_description(f"[+] lookup for {_fObject['favhash']}")
            self._iterator.update(1)
            print(_fObject['favhash'])
            try:
                _ = _alreadyScanned[_fObject['favhash']]
            except KeyError:
                found_ips = "not-found"
                if _fObject['favhash'] != "not-found":
                    found_ips = self.shodanSearch(_fObject['favhash'])
                _alreadyScanned.update({_fObject['favhash']: found_ips})
            found_ips = _alreadyScanned[_fObject['favhash']]
            _fObject.update({'found_ips': found_ips})
            
            if self.show:
                self._iterator.write("-"*25)
                self._iterator.write(f"[{_fObject['_origin']}]")
                del _fObject['_origin']
                for _atr in _fObject:
                    self._iterator.write(f"--> {_atr:<10} :: {_fObject[_atr]}")
            
            if self.output:
                _tcObj = _cObj
                _tcObj.update(_fObject)
                _t = self._output['type']
                if _t.lower() == 'csv':
                    self._output['file'].write(','.join(str(_tcObj[k]) for k in _tcObj)+'\n')
                elif _t.lower() == 'json':
                    self._output['file'].write(json.dumps(_tcObj)+'\n')
                else:
                    self._iterator.write("[x] Output format not supported, closing.")
                    exit(1)
    
    def faviconHash(self, data, web_source=None):
        if web_source:
            b64data = base64.encodebytes(data).decode()
        else:
            b64data = base64.encodebytes(data)
        return mmh3.hash(b64data)

    def searchFaviconHTML(self, link):
        data = requests.get(link, stream=True, verify=False)
        soup = BeautifulSoup(data.content, 'html.parser')
        searchIcon = soup.find('link', rel='icon')
        if searchIcon:
            iconLink = searchIcon.get("href")
            if not iconLink.startswith("http"):
                iconLink = link + "/" + iconLink
            return requests.get(iconLink, verify=False)
        return "not-found"

    def shodanSearch(self, favhash):
        time.sleep(1)
        results = self.shodan.search(f"http.favicon.hash:{favhash}")
        return '|'.join([s['ip_str'] for s in results["matches"]])

    def deepConnectionLens(self, response):
        mIP = 'not-found'
        mISP = 'not-found'
        if response.status_code == 200:
            try:
                mIP = list(response.raw._connection.sock.getpeername())[0]
                mISP = IPWhois(mIP).lookup_whois()['nets'][0]['name']
            except AttributeError:
                try:
                    mIP = list(response.raw._connection.sock.socket.getpeername())[0]
                    mISP = IPWhois(mIP).lookup_whois()['nets'][0]['name']
                except AttributeError:
                    pass
        if mIP == 'not-found':
            self._iterator.write(f"[x] There's problem when getting icon for {response.url.split('/')[2]} with status code: {response.status_code}" )
        return {
            'mIP': mIP,
            'mISP': mISP
        }
    
    def get_user_agent(self):
        try:
            return self.ua.random
        except FakeUserAgentError:
            return "Mozilla/5.0 (X11; Linux x86_64; rv:69.0) Gecko/20100101 Firefox/69.0"

if __name__ == '__main__':
    FavUpApp = FavUp(show=True)
