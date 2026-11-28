# IPScope v0.9.1

A Reverse IP lookup tool: give it an IP address, a range, an ASN or a domain, and it returns the domains hosted on it, from several data sources. It has a command-line interface and a desktop app, and it handles tens of thousands of IPs in one run.

## Install (Windows / Linux / macOS)

Requires Python 3.10 or newer.

```bash
cd ipscope
pip install -e .
```

## Desktop app

```bash
pip install -e .\[gui]
ipscope-gui          # or: ipscope gui
```

A dark desktop UI built with pywebview:

|Page|What it does|
|-|-|
|**Scan**|Enter targets or import them from a file, pick a mode and options, live progress and a running log|
|**Results**|IPs with provider and hosting type, status filters, search by domain, address or technology, group by root domain, copy, open in browser, export|
|**History**|Every scan, with resume, open and delete|
|**Local index**|Build and manage your own offline IP → domain index|
|**API Keys**|Add and remove keys; sources switch on automatically once a key is set|
|**Settings**|Defaults, data sources, speed options, privacy, cache and data folder|

Scans run in the background. **Stop** pauses a scan and you can resume it later from History. The app and the CLI share the same database.

## Windows build (.exe)

The build produces an `IPScope` folder with two programs that share the same files:

* **`IPScope.exe`**: the desktop app, no console window
* **`ipscope.exe`**: the command line

It also produces an installer, `IPScope-Setup-x.y.z.exe`, which creates Start menu and desktop shortcuts, can add `ipscope` to your PATH, and checks that WebView2 is installed.

### Option 1: build on a Windows machine

1. Install Python 3.10+ from python.org and tick **Add to PATH**.
2. For the installer as well, install Inno Setup 6.
3. Run:

```bat
   packaging\\build.bat
   ```

The output goes to `dist\\IPScope\\` (the program) and `dist\\installer\\` (the installer).

### Option 2: GitHub Actions (nothing to install)

1. Push the project to a GitHub repository.
2. In the **Actions** tab, choose **Build Windows**; it also runs on every push.
3. When it finishes, the installer and a portable zip are published as a **Release** (named after the version in `pyproject.toml`).

### Notes

* **WebView2:** the app needs the Microsoft Edge WebView2 Runtime. It is included in Windows 11 and updated Windows 10. On Windows Server it usually has to be installed by hand. Without it the window opens unstyled and does nothing.
* **Antivirus:** programs built with PyInstaller are sometimes flagged by mistake. UPX is not used and version info is embedded to reduce this. The complete fix is signing the files with a code-signing certificate, especially if you distribute them.
* **Start-up errors:** if the app does not open, details are saved to `%USERPROFILE%\\.ipscope\\gui-error.log`.

## Finding IPs that host many sites

```bash
ipscope scan AS47583 --max-hosts 2048 --preset fast --label hostinger   # Hostinger
ipscope scan AS22612 --max-hosts 2048 --preset fast --label namecheap   # Namecheap
ipscope top -n 100 --min-domains 200 -o busy\_ips.txt                    # top 100 IPs, no CDN
```

## Quick start (CLI)

```bash
ipscope scan 8.8.8.8                          # one IP
ipscope scan 1.2.3.0/28                       # a CIDR range
ipscope scan example.com                      # a domain (resolved to its IP first)
ipscope scan AS24940 --max-hosts 4096         # every range of an ASN
ipscope scan -f ips.txt -o results.csv        # from a file, save as CSV
ipscope scan 8.8.8.8 -V                       # check who is still on the same IP
ipscope scan 8.8.8.8 --only-active -o live.txt
ipscope scan 8.8.8.8 --active                 # read TLS certificates from the server
ipscope scan -f ips.txt -q > domains.txt      # domains only
```

## IP info and CDN detection

Every IP is looked up for its ASN and provider through Team Cymru DNS. This is free and needs no key; turn it off with `--no-ip-info`. Each IP is classified as one of:

|Type|Meaning|
|-|-|
|`cdn-edge`|The IP belongs to a CDN (Cloudflare, Akamai, Fastly, Imperva…). The results are unrelated sites and the real server is hidden|
|`shared`|50 or more domains: shared hosting|
|`multi-site`|5 to 49 domains|
|`single-site`|1 to 4 domains|

A clear warning is shown when an IP belongs to a CDN.

## ASN input

`ipscope scan AS13335` fetches every IPv4 range announced by the ASN from RIPEstat. Also free, no key.

* The total size is capped by `--max-hosts`; smaller ranges are scanned first.
* IPv6 ranges are skipped because they are far too large to enumerate.

## Website probe (`--probe`)

```bash
ipscope scan 5.9.10.10 -V --probe -o report.csv
```

For each domain it records the HTTP status, the final URL after redirects, the page title (Arabic supported), the Server header and the technologies in use.

* **Technologies:** about 40 are detected, such as WordPress, Laravel, Next.js, Shopify, Cloudflare and nginx. With `-V` only active domains are probed.
* **Limit:** `--probe-limit 200` per IP; the highest-confidence domains go first.
* **Note:** this is an **active** check, so it contacts the sites themselves.

## Free methods with no API

### 1\. Contact the server directly (`--active`)

```bash
ipscope scan 5.9.10.10 --active
```

* **`tls`** reads TLS certificates on 10 ports at once:

  * Web: 443, 8443
  * cPanel, WHM and Webmail: 2083, 2087, 2096
  * Mail: 465, 993, 995
  * SMTP with STARTTLS: 25, 587 (the server name is also read from the greeting)
* **`http`** requests `http(s)://IP` directly and picks up redirects, `canonical` links and `og:url`.
* **Default certificates** (`localhost.localdomain`, `default.domain`, Traefik, Kubernetes…) are filtered out automatically.

This works well for servers hosting one or a few sites. On shared hosting it only reveals the default site.

### 2\. Your own local index (`local`)

```bash
ipscope index build domains.txt            # import + resolve
ipscope index add com.zone.gz              # a zone file (e.g. from ICANN CZDS)
ipscope index add fdns\_a.json.gz --only 5.9.0.0/16 --only 51.75.0.0/16   # Rapid7 FDNS, your ranges only
ipscope index resolve                      # resumes where it stopped (Ctrl+C is safe)
ipscope index resolve --retry-failed       # retry the ones that failed
ipscope index resolve --refresh-days 30    # refresh old names
ipscope index stats
ipscope index lookup 5.9.10.10
ipscope index top -n 100 -o busiest.txt    # IPs with the most domains in the index
```

Once the index has data, the `local` source is on automatically at the start of every scan. It answers instantly, offline, with no limits. The **Local index** page in the app does the same things.

**Local index first.** When the index already knows an IP, the answer comes from it and the online sources are skipped for that IP; IPs it does not know fall through to the other sources as usual. This is on by default (**Settings → Local index first**, or `--no-local-first` on the CLI) and applies to every mode, not only Offline.

Measured numbers (with a fake DNS that answers after 50 ms):

|Operation|Speed|
|-|-|
|Import 1 million domains|5.9 s|
|Import 1 million Rapid7 FDNS records|9.5 s (no resolve)|
|Resolve|\~8,900 names/s, so a million names in about two minutes|
|Index lookups|\~136,000 IPs/s|
|Index size|\~232 MB per 2 million names|

> The full Rapid7 `fdns\_a` file is over 30 GB compressed. Use `--only` with your own ranges to keep the index small.

## Performance with tens of thousands of IPs

Measured with instant fake sources, to show the speed of the tool itself without any API:

|Case|Result|
|-|-|
|50,000 IPs (250k domains)|18.7 s, flat memory \~95 MB|
|2,000 shared-hosting IPs (600k domains)|26.6 s, memory \~108 MB|
|DNS validation (`-V`)|\~3,800 domains/s (was 119)|
|Opening 600k domains in the app|under 1 s; search and paging take 0.1 to 1.5 s|
|CSV export of 600k rows|3.5 s, with no memory growth|

How it works:

* **Storage:** every domain is stored as a row in the database. The app, the CLI and the exports read from it page by page, or as a stream.
* **DNS validation:** async dnspython, 200 queries at once, with a cache; a domain that appears on several IPs is asked about only once. A failed query (timeout) marks the domain `unknown`, not `dead`.
* **A source that runs out of quota, or whose keys are all rejected,** is switched off for the rest of the scan instead of failing on every IP. If every source stops, the scan stops and can be resumed later.
* **The CLI on big scans** prints a summary and the top IPs only; the full results go out with `-o` or `-q`.

**Note:** real speed depends on the APIs' limits. With free sources (1 request/s), 50,000 IPs take about 14 hours.

## Root domains and confidence

* `--roots` groups results by root domain, e.g. `shop.example.co.uk` becomes `example.co.uk`. It uses the Public Suffix List and works offline.
* **Confidence (0-100):** based on how many sources confirmed the domain and its DNS status.

  * One source = 40, two = 65, three or more = 85
  * active adds 15, historical subtracts 15, dead subtracts 30

```bash
ipscope scan 5.9.10.10 --roots -q > roots.txt
```

## Stop and resume

Every IP is saved to the database the moment it finishes.

```bash
ipscope scan -f big\_list.txt --label "client-x"   # press Ctrl+C at any time
ipscope resume                                    # continues the last unfinished scan
ipscope resume 7                                  # or a specific one
ipscope history                                   # all scans
ipscope show 7 -o report.json                     # export an old scan
ipscope delete 7
```

If the machine shuts down or the program crashes, `resume` still works.

## Cache

Each source's answer for each IP is kept for 24 hours, so re-scanning does not use up API limits.

```bash
ipscope scan 8.8.8.8 --cache-ttl 72      # cache lifetime in hours
ipscope scan 8.8.8.8 --no-cache          # ignore the cache
ipscope cache stats
ipscope cache clear --older-than 168
```

Errors are never cached, so a failed request is retried next time.

## API keys

```bash
ipscope keys set virustotal                # prompts for the key (hidden)
ipscope keys set virustotal KEY2 --add     # an extra key for rotation
ipscope keys list                          # shown masked: abcd…1234
ipscope keys delete shodan
```

* **Storage:** Windows Credential Manager or macOS Keychain. With no system keyring, keys are kept in `\~/.ipscope/keys.json`, readable by the owner only.
* **Environment variables** override stored keys, e.g. `IPSCOPE\_VIRUSTOTAL\_KEY=k1,k2`.
* **Rotation:** if a key is rejected (401/403) or its quota is used up (429, or "API count exceeded" on HackerTarget), the next key is used automatically.
* **Sources that need a key** are added to the scan automatically once a key is set, and skipped with a notice otherwise.

## Sources

|Source|Key|Notes|
|-|-|-|
|`local`|-|Your local index: instant, no limits (`ipscope index build`)|
|`dnsrift`|optional|DNSRift API, free without a key|
|`thc`|-|ip.thc.org, free without a key, very large database. Limit about 0.5 requests/s|
|`hackertarget`|optional|The free tier allows 20 queries a day|
|`otx`|optional|AlienVault passive DNS, with first/last seen dates|
|`internetdb`|-|Shodan InternetDB, free|
|`ptr`|-|Reverse DNS|
|`webscan`|-|webscan.cc, free but not officially documented. **Off by default**|
|`virustotal`|**required**|Passive DNS, the free tier allows 4 requests/minute|
|`securitytrails`|**required**||
|`shodan`|**required**||
|`rapiddns`|**required**|The official API, needs a Pro membership|
|`networksdb`|**required**|The official API, the free key gives 1,000 requests a month|
|`tls` / `http`|-|**Active**: they connect to the server itself (`--active`)|

### Modes (presets)

```bash
ipscope scan -f ips.txt --preset fast      # only the fastest large sources
ipscope scan -f ips.txt --preset free      # every free passive source
ipscope scan -f ips.txt --preset full      # everything you have set up, plus tls and http
ipscope scan -f ips.txt --preset offline   # local index only, no network
```

The same modes are buttons on the Scan page of the app.

## Speed and display options

|Option|In the app (Settings)|CLI|
|-|-|-|
|Local index answers first|Local index first|`--local-first` / `--no-local-first`|
|Keep root domains only|Save root domains only|`--roots-only`|
|Stop at the first source that finds results|Stop at the first match|`--first-hit`|
|Skip IPs scanned before|Skip IPs scanned before|`--skip-scanned`|
|Hide source names (for screen recording)|Hide source names|-|
|Save every domain to `results.txt`|Save every domain to results.txt|always on (`IPSCOPE\_NO\_RESULTS\_TXT=1` to disable)|

* **Root domains only:** the root domain takes the best status of its subdomains. If `shop.example.com` is live on the IP, `example.com` is recorded as active.
* **Hide source names:** removes source names from the scan page, results, log, sidebar and exports. Choosing sources lives in Settings; the Scan page only has the mode buttons. The scan log never shows provider or CDN names; those are on the Results page.
* **`results.txt`:** every domain found is appended, one per line, to `\~/.ipscope/results.txt`. The file only grows: nothing is removed from it, even when you delete scans from History. A domain is not repeated within one run, but a later run can add it again.

## Subdomains

```bash
ipscope subdomains example.com                 # from local, dnsrift, thc, otx, crt.sh and rapiddns
ipscope subdomains example.com -V -o subs.csv  # with resolve: which are live, and on which IP
ipscope subdomains -f domains.txt -q > all.txt
```

This is entirely passive: nothing is sent to the target itself.

Each source has its own rate limit and retries with a growing wait.

## Domain status (with `-V`)

* **active**: still points to the same IP
* **historical**: used to be on it and moved away
* **dead**: has no DNS record

## Export

The format follows the file extension:

* `.txt`: domains only
* `.csv`: opens straight in Excel. Includes ASN, provider, hosting type, root domain, confidence and probe results
* `.json`: complete, with errors

## Data and proxy

* Everything lives in `\~/.ipscope/` (database `ipscope.db`, index `index.db`, domain list `results.txt`). Change the location with `--home PATH` or `IPSCOPE\_HOME`.
* Proxy: the tool respects `HTTPS\_PROXY` and `HTTP\_PROXY`.

## Adding a source

```python
# ipscope/sources/mysource.py
class MySource(Source):
    name = "mysource"
    rate = 1.0                        # requests per second
    key\_env = "IPSCOPE\_MYSOURCE\_KEY"
    requires\_key = True

    def \_auth(self, key):             # (params, headers) for every request
        return {}, {"X-Key": key}

    async def \_lookup(self, ip):
        data = await self.\_fetch(f"https://api.example/{ip}", as\_json=True)
        return \[DomainRecord(d, self.name) for d in (data or {}).get("domains", \[])]
```

Then add it to `REGISTRY` in `ipscope/sources/\_\_init\_\_.py`. Retry, key rotation and caching work on their own.

## Tests

```bash
pip install pytest
pytest -q
```

The tests never touch your real keyring.

## Disclaimer

Use it only on targets you are authorized to scan, and follow each API's terms of service.

