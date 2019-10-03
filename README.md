# Fav-up
Lookups for real IP starting from the favicon icon and using Shodan.

![img](https://i.imgur.com/oio0qCh.png)
![img2](https://i.imgur.com/NbkqGbY.png)


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
# if you want to print to stdout
f.show = True 
f.run()
# returns the list of the IPs found on Shodan
f.realIPs
# returns the hash of the favicon
f.favhash
```

### All attributes
| Variable | Type |
|-:|:-|
| FavUp.show        | bool
| FavUp.key         | str
| FavUp.keyFile     | str
| FavUp.shodanCLI   | bool
| FavUp.faviconFile | str
| FavUp.faviconURL  | str
| FavUp.web         | str
| FavUp.favhash     | int
| FavUp.shodan      | Shodan class
| FavUp.maskIP      | str
| FavUp.maskISP     | str
| FavUp.realIPs     | list[str]


# Compatibility
At least `python3.6` is required due to spicy syntax.

# Publications

Publication section coming soon

# Credits

Conceived by Francesco Poldi [noneprivacy](https://twitter.com/noneprivacy), build with Aan Wahyu [Petruknisme](https://twitter.com/petruknisme)

[stanley_HAL](https://twitter.com/stanley_HAL) told me how Shodan calculates the favicon hash.

[What is Murmur3?](https://www.sderosiaux.com/articles/2017/08/26/the-murmur3-hash-function--hashtables-bloom-filters-hyperloglog/)

[More about Murmur3 and Shodan](https://www.cnblogs.com/miaodaren/p/9177379.html)
