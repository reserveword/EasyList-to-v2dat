# EasyList-to-v2dat

This project transforms EasyList-like rule files to .dat files used by v2ray.

## How it works

Easylist has very complex rules, but we don't need to implement it all.
Since v2ray can only read domain and ip, we only need to extract that
and discard the rest (protocols, ports, html/css tags, etc.)

This program works under this rule now:

`^ *(@@)? *(\|{0,2}) *(https?://)?(([a-zA-Z][-a-zA-Z0-9]*\.[-a-zA-Z0-9.]*)|(?:[0-9]{1,3}\.){3}[0-9]{1,3}|\[?(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\]?|\[?[0-9-fA-F:]*::[0-9-fA-F:]*\]?)(/)?|^ */(.*)/`

Now let me explain this.

1. `^ *(@@)? *(\|{0,2}) *` detects prefix: `@@`, `||`, `|`.

   In EasyList, `@@` means whitelist; `||` means suffix; `|` means prefix.
2. `(https?://)?(([a-zA-Z][-a-zA-Z0-9]*\.[-a-zA-Z0-9.]*)|(?:[0-9]{1,3}\.){3}[0-9]{1,3}|\[?(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\]?|\[?[0-9-fA-F:]*::[0-9-fA-F:]*\]?)` detects a domain, an IPv4 address or an IPv6 address.

   1. `(https?://)?` detects HTTP or HTTPS scheme.
   2. `[a-zA-Z][-a-zA-Z0-9]*\.[-a-zA-Z0-9.]*` detects a domain. It matches wild, only ensures the first character is letter, includes a dot(.), composed of letter, number, hyphen and dot.
   3. `(?:[0-9]{1,3}\.){3}[0-9]{1,3}` detects an IPv4 address. Also very wild.
   4. `\[?(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\]?` detects an IPv6 address without "::".
   5. `\[?[0-9-fA-F:]*::[0-9-fA-F:]*\]?`  detects an IPv6 address with "::". Very wild.

3. `(/)?` detects the end of host in a URL. It looks like this: `http://www.example.com/example?field=value`, and we need nothing other than `www.example.com`, so the match ends here.
4. `^ */(.*)/` detects a regexp.

Gathering all conditions above, we have 5 different kind of patterns:

1. suffix match (If `||` or `(/)?` applys)
2. prefix match (If `|` or `(https?://)?` applys)
3. full match (If 1. and 2. applys, or if result is an IP address)
4. keyword match (If none above applys and it's not a regexp)
5. regexp match (if `^ */(.*)/` applys)

Note that v2ray only support 1. 3. 4. and 5., so 2. falls back to 4.

## How to use its outputs

### If ips and sites are output separately

    - ext:ips.dat:match for matched ips
    - ext:ips.dat:pass for whitelisted ips
    - ext:sites.dat:match for matched domains
    - ext:sites.dat:pass for whitelisted domains

### If all are output altogether

    - ext:output.dat:ip for matched ips
    - ext:output.dat:!ip for whitelisted ips
    - ext:output.dat:site for matched domains
    - ext:output.dat:!site for whitelisted domains

## Usage

```
Usage: easylist-to-v2dat [OPTIONS]
Transforms EasyList-like rule files to .dat files used by v2ray.
If any FILE is - or missing, use STDIN or STDOUT instead.
  -i --input=FILE         transforms EasyList-like FILE
  -o --output=FILE        output .dat file to FILE
  -s --sites=FILE         output sites to FILE, instead of to -o
  -p --ips=FILE           output ips to FILE, instead of to -o
  -v --verbose            output extra logs to STDOUT (or STDERR if occupied)
```

# Credits

This program is based on [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community) and [v2fly/geoip](https://github.com/v2fly/geoip)
