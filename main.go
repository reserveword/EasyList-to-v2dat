package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"regexp"
	"sort"

	router "github.com/v2fly/v2ray-core/v5/app/router/routercommon"
	"github.com/v2fly/v2ray-core/v5/infra/conf/rule"
	"google.golang.org/protobuf/proto"
	"rsc.io/getopt"
)

var (
	input   = flag.String("input", "-", "transforms EasyList-like FILE")
	output  = flag.String("output", "-", "output sites to FILE")
	sites   = flag.String("sites", "", "output sites to FILE, same as -o")
	ips     = flag.String("ips", "", "output ips to FILE, instead of discarding")
	verbose = flag.Bool("verbose", false, "output extra logs to STDOUT (or STDERR if occupied)")
	help    = flag.Bool("help", false, "print this usage and exit")
)

const regstr = `^ *(@@)? *(\|{0,2}) *(https?://)?(([a-zA-Z][-a-zA-Z0-9]*\.[-a-zA-Z0-9.]*)|(?:[0-9]{1,3}\.){3}[0-9]{1,3}|\[?(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\]?|\[?[0-9-fA-F:]*::[0-9-fA-F:]*\]?)(/)?|^ */(.*)/`

var regex = regexp.MustCompile(regstr)

const httpsRegstr = `http[s:\\/?]*/|([0-9a-zA-Z\]\).+*?}])\\?/[^\]\)\n]+(\[[^\]\n]*\]|\([^\)\n]\))*[^\]\)\n]*$`

var httpsRegex = regexp.MustCompile(httpsRegstr)

const (
	PREFIXMATCH byte = 1 << 0
	SUFFIXMATCH byte = 1 << 1
	REGEXPMATCH byte = 1 << 2
	WHITELIST   byte = 1 << 0
	SITEMATCH   byte = 1 << 1
)

const (
	KEYWORDMATCH byte = 0
	FULLMATCH    byte = PREFIXMATCH | SUFFIXMATCH
	IPMATCH      byte = 0
	BLACKLIST    byte = 0
)

type Entry struct {
	Type  byte
	Value string
	// Attrs []*router.Domain_Attribute
}

type List struct {
	Name  string
	Entry []Entry
}

func (l *List) toIPProto() (*router.GeoIP, error) {
	site := &router.GeoIP{
		CountryCode: l.Name,
	}
	for _, entry := range l.Entry {
		cidr, err := rule.ParseIP(entry.Value)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		site.Cidr = append(site.Cidr, cidr)
	}
	return site, nil
}

func (l *List) toProto() (*router.GeoSite, error) {
	site := &router.GeoSite{
		CountryCode: l.Name,
	}
	for _, entry := range l.Entry {
		switch entry.Type {
		case SUFFIXMATCH:
			site.Domain = append(site.Domain, &router.Domain{
				Type:  router.Domain_RootDomain,
				Value: entry.Value,
				// Attribute: entry.Attrs,
			})
		case REGEXPMATCH:
			site.Domain = append(site.Domain, &router.Domain{
				Type:  router.Domain_Regex,
				Value: entry.Value,
				// Attribute: entry.Attrs,
			})
		case KEYWORDMATCH:
			site.Domain = append(site.Domain, &router.Domain{
				Type:  router.Domain_Plain,
				Value: entry.Value,
				// Attribute: entry.Attrs,
			})
		case FULLMATCH, PREFIXMATCH:
			site.Domain = append(site.Domain, &router.Domain{
				Type:  router.Domain_Full,
				Value: entry.Value,
				// Attribute: entry.Attrs,
			})
		default:
			return nil, errors.New("unknown domain type: " + string(entry.Type))
		}
	}
	return site, nil
}

func main() {
	getopt.Alias("i", "input")
	getopt.Alias("o", "output")
	getopt.Alias("s", "sites")
	getopt.Alias("p", "ips")
	getopt.Alias("v", "verbose")
	getopt.Alias("h", "help")
	getopt.Parse()
	if *help {
		usage()
		os.Exit(0)
	}
	var infile, ipfile, sitefile *os.File
	// infile
	if input == nil || *input == "" || *input == "-" { // input file
		infile = os.Stdin
	} else {
		infile, err := os.Open(*input)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer infile.Close()
	}
	// outfiles - ipfile
	if ips == nil || *ips == "" {
		ipfile = nil
	} else if *ips == "-" {
		ipfile = os.Stdout
	} else {
		ipfile, err := os.OpenFile(*ips, os.O_RDWR|os.O_CREATE, 644)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer ipfile.Close()
	}
	// outfiles - sitefile
	if sites == nil || *sites == "" {
		sites = output
	}
	if sites == nil || *sites == "" || *sites == "-" {
		if ipfile == os.Stdout {
			sitefile = nil
		} else {
			sitefile = os.Stdout
		}
	} else {
		sitefile, err := os.OpenFile(*sites, os.O_RDWR|os.O_CREATE, 644)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer sitefile.Close()
	}
	var lists = [4]List{}
	lists[IPMATCH|BLACKLIST] = List{Name: "ip", Entry: []Entry{}}
	lists[IPMATCH|WHITELIST] = List{Name: "!ip", Entry: []Entry{}}
	lists[SITEMATCH|BLACKLIST] = List{Name: "site", Entry: []Entry{}}
	lists[SITEMATCH|WHITELIST] = List{Name: "!site", Entry: []Entry{}}
	scanner := bufio.NewScanner(infile)
	for scanner.Scan() {
		bytes := scanner.Bytes()
		match := regex.FindSubmatch(bytes)
		var pattern byte = 0
		var tag byte = 0
		if match == nil {
			continue // empty or !comment line
		}
		if len(match[1]) == 2 { // @@
			tag |= WHITELIST
		}
		if len(match[2]) == 1 { // |
			pattern |= PREFIXMATCH
		} else if len(match[2]) == 2 { // ||
			pattern |= SUFFIXMATCH
		}
		if len(match[3]) != 0 { // (https?://)
			pattern |= PREFIXMATCH
		}
		if len(match[5]) != 0 { // is a domain
			tag |= SITEMATCH
		}
		if len(match[6]) != 0 { // (/)
			pattern |= SUFFIXMATCH
		}

		if len(match[4]) != 0 {
			lists[tag].Entry = append(lists[tag].Entry, Entry{pattern, string(match[4])})
		} else if len(match[7]) != 0 { // /(.*)/
			pattern = REGEXPMATCH // once regexp, always regexp
			tag |= SITEMATCH      // regexp only works on site
			regexWithoutHttps := httpsRegex.ReplaceAllString(string(match[7]), "$1")
			fmt.Fprintln(os.Stderr, regexWithoutHttps)
			_, err := regexp.Compile(regexWithoutHttps)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%v, from url regexp `%s`\n", err, string(match[7]))
				continue
			}
			lists[tag].Entry = append(lists[tag].Entry, Entry{pattern, regexWithoutHttps})
		}
		// lists[tag].Entry = append(lists[tag].Entry, Entry{pattern, string(match[4])})
	}
	protoList := new(router.GeoSiteList)
	ipsList := new(router.GeoIPList)
	for i, list := range lists {
		if byte(i)&SITEMATCH == SITEMATCH && sitefile != nil {
			site, err := list.toProto()
			if err != nil {
				fmt.Fprintln(os.Stderr, "Failed: ", err)
				os.Exit(1)
			}
			protoList.Entry = append(protoList.Entry, site)
		} else if byte(i)&SITEMATCH == IPMATCH && ipfile != nil {
			ip, err := list.toIPProto()
			if err != nil {
				fmt.Fprintln(os.Stderr, "Failed: ", err)
				os.Exit(1)
			}
			ipsList.Entry = append(ipsList.Entry, ip)
		}
	}
	sort.SliceStable(protoList.Entry, func(i, j int) bool {
		return protoList.Entry[i].CountryCode < protoList.Entry[j].CountryCode
	})
	protoBytes, err := proto.Marshal(protoList)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed:", err)
		os.Exit(1)
	}
	sitefile.Write(protoBytes)
	sort.SliceStable(ipsList.Entry, func(i, j int) bool {
		return ipsList.Entry[i].CountryCode < ipsList.Entry[j].CountryCode
	})
	ipsBytes, err := proto.Marshal(ipsList)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed:", err)
		os.Exit(1)
	}
	ipfile.Write(ipsBytes)
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage: easylist-to-v2dat [OPTIONS]
Transforms EasyList-like rule files to .dat files used by v2ray.
If any FILE is - or missing, use STDIN or STDOUT instead.

Options:
`)
	getopt.PrintDefaults()
}
