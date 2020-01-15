# Fav-up
Lookups for real IP starting from the favicon icon and using Shodan.

![img](https://i.imgur.com/ejPmx8T.png)
![img2](https://i.imgur.com/7wf5AL7.png)

# Installation
- `pip3 install -r requirements.txt`
- Shodan API key (**not** the free one)

# Usage

## CLI
First define how you pass the API key:

- `-k` or `--key` to pass the key to the stdin
- `-kf` or `--key-file` to pass the filename which get the key from
- `-sc` or `--shodan-cli` to get the key from Shodan CLI (if you initialized it)

As of now, this tool can be used in three different ways:

- `-ff` or `--favicon-file`: you store locally a favicon icon which you want to lookup
- `-fu` or `--favicon-url`: you don't store locally the favicon icon, but you know the exact url where it resides
- `-w` or `--web`: you don't know the URL of the favicon icon, but you still know that's there
- `-fh` or `--favicon-hash`: you know the hash and want to search the entire internet.

You can specify input files which may contain urls to domain, to favicon icons, or simply locations of locally stored icons:

- `-fl`, `--favicon-list`: the file contains the full path of all the icons which you want to lookup
- `-ul`, `--url-list`: the file contains the full URL of all the icons which you want to lookup
- `-wl`, `--web-list`: the contains all the domains which you want to lookup

You can also save the results to a CSV/JSON file:

- `-o`, `--output`: specify the output and the format, e.g.: `results.csv` will save to a CSV file (the type is automatically recognized by the extension of the output file)

### Examples
#### Favicon-file
`python3 favUp.py --favicon-file favicon.ico -sc`

#### Favicon-url
`python3 favUp.py --favicon-url https://domain.behind.cloudflare/assets/favicon.ico -sc`

#### Web
`python3 favUp.py --web domain.behind.cloudflare -sc`


## Module

```python
from favUp import FavUp

f = FavUp()          
f.shodanCLI = True
f.web = "domain.behind.cloudflare"
f.show = True 
f.run()

for result in f.faviconsList:
    print(f"Real-IP: {result['found_ips']}")
    print(f"Hash: {result['favhash']}")
```

### All attributes
| Variable | Type |
|-:|:-|
| FavUp.show         | bool
| FavUp.key          | str
| FavUp.keyFile      | str
| FavUp.shodanCLI    | bool
| FavUp.faviconFile  | str
| FavUp.faviconURL   | str
| FavUp.web          | str
| FavUp.shodan       | Shodan class
| FavUp.faviconsList | list[dict]

`FavUp.faviconsList` stores all the results, the key fields depend by the type of the lookup you want to do.

In case of `--favicon-file` or `--favicon-list`:

- `favhash` stores the hash of the favicon icon
- `file` stores the path

In case of `--favicon-url` or `--url-list`:

- `favhash` stores the hash of the favicon icon
- `url` stores the URL of the favicon icon
- `domain` stores the domain name
- `maskIP` stores the "fake" IP (e.g. the Cloudflare one)
- `maskISP` store the ISP name associated to the `maskIP`

In case of `--web` or `--web-list`:

- `favhash` stores the hash of the favicon icon
- `domain` stores the domain name
- `maskIP` stores the "fake" IP (e.g. the Cloudflare one)
- `maskISP` store the ISP name associated to the `maskIP`

(in this case the URL of the favicon icon is returned by the `href` attribute of `<link rel='icon'>` HTML element)

If, while searching for the favicon icon, nothing useful is found, `not-found` will be returned.

In all three cases, `found_ips` field is added for every checked entry. If no IP(s) have been found, `not-found` will be returned.

# Compatibility
At least `python3.6` is required due to spicy syntax.

# Feedback/Suggestion
Feel free to open any issue, your feedback and suggestions are always welcome <3

# Publications

[Unveiling IPs behind Cloudflare](https://pielco11.ovh/posts/cloud-hunting/) by [@noneprivacy](https://twitter.com/noneprivacy)

# Disclaimer 
This tool is for educational purposes only. The authors and contributors don't take any responsibility for the misuse of this tool. Use It At Your Own Risk! 

# Credits

Conceived by Francesco Poldi [noneprivacy](https://twitter.com/noneprivacy), build with Aan Wahyu [Petruknisme](https://twitter.com/petruknisme)

[stanley_HAL](https://twitter.com/stanley_HAL) told me how Shodan calculates the favicon hash.

[What is Murmur3?](https://www.sderosiaux.com/articles/2017/08/26/the-murmur3-hash-function--hashtables-bloom-filters-hyperloglog/)

[More about Murmur3 and Shodan](https://www.cnblogs.com/miaodaren/p/9177379.html)
