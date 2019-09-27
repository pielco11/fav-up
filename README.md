# Fav-up
IP lookup from favicon using Shodan

![img](https://i.imgur.com/4S6NIx8.png)

Lookups for real IP starting from the favicon icon and using Shodan.

# Installation
- `pip3 install -r requirements.txt`
- Shodan API key

# Usage

First thing first, create a file named `SHODAN_API.txt` and place there your API key.

As of now, this tool can be used in three different ways:

- `--favicon-file`: you store locally a favicon icon which you want to lookup
- `--favicon-url`: you don't store locally the favicon icon, but you know the exact url where it resides
- `--web`: you don't know the URL of the favicon icon, but you still know that's there

# Examples

## Favicon-file
`python3 favUp.py --favicon-file favicon.ico`

## Favicon-url
`python3 favUp.py --favicon-url https://domain.behind.cloudflare/assets/favicon.ico`

## Web
`python3 favUp.py --web https://domain.behind.cloudflare`

# Compatibility
At least `python3.6` is required due to spicy syntax.

# Credits
As you may see, I created this tool.

[stanley_HAL](https://stanley_HAL) told me how Shodan calculates the favicon hash.

[What is Murmur3?](https://www.sderosiaux.com/articles/2017/08/26/the-murmur3-hash-function--hashtables-bloom-filters-hyperloglog/)

[More about Murmur3 and Shodan](https://www.cnblogs.com/miaodaren/p/9177379.html)