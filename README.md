<!--[![alt text][1.1]][1] [![alt text][6.1]][6]-->

[1]: https://twitter.com/unethicalsalt
[1.1]: http://i.imgur.com/tXSoThF.png

[6]: http://www.github.com/ekultek
[6.1]: http://i.imgur.com/0o48UoR.png

# WhatWaf?

WhatWaf is an advanced firewall detection tool who's goal is to give you the idea of "There's a WAF?". WhatWaf works by detecting a firewall on a web application, and attempting to detect a bypass (or two) for said firewall, on the specified target. 

#### _SIDE-NOTE: Any issue that is not the newest version of WhatWaf will be closed without discussion_

# Helpful links
 - Supporting [whatwaf](https://github.com/Ekultek/WhatWaf/wiki/WhatWaf-and-XMR) with XMR mining
 - Create an [issue](https://github.com/Ekultek/WhatWaf/issues/new)
 - Read the [manual](https://github.com/Ekultek/WhatWaf/wiki/Functionality)
 - WhatWafs [Features](https://github.com/Ekultek/WhatWaf/blob/master/.github/README2.md#features)
 - [Installing](https://github.com/Ekultek/WhatWaf/blob/master/.github/README2.md#installation) WhatWaf
 - PoC
   - [Demo video](https://github.com/Ekultek/WhatWaf/blob/master/.github/README2.md#demo-video)
   - [Proof of Concept images](https://github.com/Ekultek/WhatWaf/blob/master/.github/README2.md#proof-of-concept)
 - [Get involved](https://github.com/Ekultek/WhatWaf/blob/master/.github/README2.md#get-involved)
 - Follow me on [![alt text][1.1]][1]
 - Follow me on [![alt text][6.1]][6]
 ---

# Possible Detectable Firewalls
 
 ```
whatwaf --wafs

	                          ,------.
	                         '  .--.  '
	,--.   .--.   ,--.   .--.|  |  |  |
	|  |   |  |   |  |   |  |'--'  |  |
	|  |   |  |   |  |   |  |    __.  |
	|  |.'.|  |   |  |.'.|  |   |   .'
	|         |   |         |   |___|
	|   ,'.   |hat|   ,'.   |af .---.
	'--'   '--'   '--'   '--'   '---'
/><s/**/cript>alert("WhatWaf?<|>v1.8($stable)");</scrip/**/t>

[00:58:55][INFO] gathering a list of possible detectable wafs
360 Web Application Firewall (360)
aeSecure (WAF)
Airlock (Phion/Ergon)
AkamaiGHost Website Protection (Akamai Global Host)
Alert Logic (SIEMless Threat Management)
AliYunDun (WAF)
Anquanbao Web Application Firewall (Anquanbao)
AnYu Web Application Firewall (Anyu Technologies)
Apache Generic
Armor Protection (Armor Defense)
Application Security Manager (F5 Networks)
ASP.NET Generic Website Protection (MS)
Apache Traffic Server (ATS web proxy)
Amazon Web Services Web Application Firewall (Amazon)
Yunjiasu Web Application Firewall (Baidu)
Barikode Web Application Firewall
Barracuda Web Application Firewall (Barracuda Networks)
Bekchy (WAF)
BIG-IP (F5 Networks)
BinarySEC Web Application Firewall (BinarySEC)
Bitninja (WAF)
BlockDos DDoS protection (BlockDos)
Chuangyu top government cloud defense platform (WAF)
Cisco ACE XML Firewall (Cisco)
CloudFlare Web Application Firewall (CloudFlare)
CloudFront Firewall (Amazon)
XSS/CSRF Filtering Protection (CodeIgniter)
Comodo Web Application Firewall (Comodo)
IBM Websphere DataPower Firewall (IBM)
Deny All Web Application Firewall (DenyAll)
DiDiYun WAF (DiDi)
DoD Enterprise-Level Protection System (Department of Defense)
DOSarrest (DOSarrest Internet Security)
dotDefender (Applicure Technologies)
DynamicWeb Injection Check (DynamicWeb)
EdgeCast Web Application Firewall (Verizon)
ExpressionEngine (Ellislab WAF)
FortiWeb Web Application Firewall (Fortinet)
Gladius network WAF (Gladius)
Google Web Services
Grey Wizard Protection
Incapsula Web Application Firewall (Incapsula/Imperva)
INFOSAFE by http://7i24.com
Instart Logic (Palo Alto)
Janusec Application Gateway (WAF)
Jiasule (WAF)
Litespeed webserver Generic Protection
Malcare (MalCare Security WAF)
Open Source Web Application Firewall (Modsecurity)
Mod Security (OWASP CSR)
NexusGuard Security (WAF)
Nginx Generic Protection
Palo Alto Firewall (Palo Alto Networks)
Anti Bot Protection (PerimeterX)
pkSecurityModule (IDS)
Powerful Firewall (MyBB plugin)
Radware (AppWall WAF)
RSFirewall (Joomla WAF)
Sabre Firewall (WAF)
SafeDog WAF (SafeDog)
SecuPress (Wordpress WAF)
Shadow Daemon Opensource (WAF)
Shield Security
Website Security SiteGuard (Lite)
SonicWALL Firewall (Dell)
Squid Proxy (IDS)
Stingray Application Firewall (Riverbed/Brocade)
StrictHttpFirewall (WAF)
Sucuri Firewall (Sucuri Cloudproxy)
Teros Web Application Firewall (Citrix)
UEWaf (UCloud)
UrlScan (Microsoft)
Varnish/CacheWall WAF
Viettel WAF (Cloudrity)
Wallarm WAF
WebKnight Application Firewall (AQTRONIX)
IBM Security Access Manager (WebSEAL)
West236 Firewall
Wordfence (Feedjit)
WTS-WAF (Web Application Firewall)
Xuanwudun WAF
Yundun Web Application Firewall (Yundun)
Yunsuo Web Application Firewall (Yunsuo)
Zscaler Cloud Firewall (WAF)
[00:58:55][INFO] WhatWaf can detect a total of 86 web application protection systems
```

# Possible Tampers

```

	                          ,------.  
	                         '  .--.  ' 
	,--.   .--.   ,--.   .--.|  |  |  | 
	|  |   |  |   |  |   |  |'--'  |  | 
	|  |   |  |   |  |   |  |    __.  | 
	|  |.'.|  |   |  |.'.|  |   |   .'  
	|         |   |         |   |___|   
	|   ,'.   |hat|   ,'.   |af .---.   
	'--'   '--'   '--'   '--'   '---'  
\"/><sCRIPT>ALeRt(\"WhatWaf?<|>v1.6.2($dev)\");</scRiPT>

[15:02:29][INFO] gathering available tamper script load paths
---------------------------------------------------------------------------
	Load path:			  |	Description:
---------------------------------------------------------------------------
content.tampers.apostrephemask            |  hiding an apostrophe by its UTF equivalent
content.tampers.apostrephenullify         |  hiding the apostrophe by passing it with a NULL character
content.tampers.appendnull                |  appending a NULL byte to the end of the payload
content.tampers.base64encode              |  encoding the payload into its base64 equivalent
content.tampers.booleanmask               |  mask the booleans with their symbolic counterparts
content.tampers.doubleurlencode           |  double URL encoding the payload characters
content.tampers.enclosebrackets           |  enclosing numbers into brackets
content.tampers.escapequotes              |  escaping quotes with slashes  
content.tampers.lowercase                 |  turning the payload into its lowercase equivalent
content.tampers.maskenclosebrackets       |  enclosing brackets and masking an apostrophe around the character in the brackets
content.tampers.modsec                    |  putting the payload in-between a comment with obfuscation in it
content.tampers.modsecspace2comment       |  obfuscating payload by passing it between comments with obfuscation and changing spaces to comments
content.tampers.obfuscatebyhtmlcomment    |  obfuscating script tags with HTML comments'
content.tampers.obfuscatebyhtmlentity     |  changing the payload characters into their HTML entities
content.tampers.obfuscatebyordinal        |  changing certain characters in the payload into their ordinal equivalent
content.tampers.prependnull               |  pre-pending a NULL character at the start of the payload
content.tampers.randomcase                |  changing the character case of the payload randomly with either upper or lower case
content.tampers.randomcomments            |  implanting random comments into the payload
content.tampers.randomdecoys              |  add decoy tags to the script  
content.tampers.randomjunkcharacters      |  adding random junk characters into the payload to bypass regex based protection
content.tampers.randomtabify              |  replacing the spaces in the payload with either the tab character or eight spaces
content.tampers.randomunicode             |  inserting random UTF-8 characters into the payload
content.tampers.randomwildcard            |  changing characters into a wildcard
content.tampers.space2comment             |  changing the spaces in the payload into a comment
content.tampers.space2doubledash          |  changing the spaces in the payload into double dashes
content.tampers.space2hash                |  changing the payload spaces to obfuscated hashes with a newline
content.tampers.space2multicomment        |  change the payload spaces to a random amount of spaces obfuscated with a comment
content.tampers.space2null                |  changing the spaces in the payload into a NULL character
content.tampers.space2plus                |  changing the spaces in the payload into a plus sign
content.tampers.space2randomblank         |  changing the payload spaces to random ASCII blank characters
content.tampers.tabifyspacecommon         |  replacing the payloads spaces with tab character (\t)
content.tampers.tabifyspaceuncommon       |  replacing the spaces in the payload with 8 spaces to simulate a tab character
content.tampers.tripleurlencode           |  triple URL encoding the payload characters
content.tampers.uppercase                 |  changing the payload into its uppercase equivalent
content.tampers.urlencode                 |  encoding punctuation characters by their URL encoding equivalent
content.tampers.urlencodeall              |  encoding all characters in the payload into their URL encoding equivalent
---------------------------------------------------------------------------
[15:02:29][INFO] total of 36 tamper scripts available
```

# Basic Help Menu

```
usage: ./whatwaf -[u|l|b|g] VALUE|PATH|PATH|PATH [-p|--pl] PAYLOAD,..|PATH [--args]

optional arguments:
  -h, --help            show this help message and exit

mandatory arguments:
  arguments that have to be passed for the program to run

  -u URL, --url URL     Pass a single URL to detect the protection
  -l PATH, --list PATH, -f PATH, --file PATH
                        Pass a file containing URL's (one per line) to detect
                        the protection
  -b FILE-PATH, --burp FILE-PATH
                        Pass a Burp Suite request file to perform WAF
                        evaluation
  -g GOOGLER-JSON-FILE, --googler GOOGLER-JSON-FILE
                        Pass a JSON file from the Googler CMD line tool (IE
                        googler -n 100 --json >> googler.json)

request arguments:
  arguments that will control your requests

  --pa USER-AGENT       Provide your own personal agent to use it for the HTTP
                        requests
  --ra                  Use a random user-agent for the HTTP requests
                        (*default=whatwaf/2.0 (Language=2.7.10;
                        Platform=Darwin))
  -H HEADER=VALUE,HEADER:VALUE.., --headers HEADER=VALUE,HEADER:VALUE..
                        Add your own custom headers to the request. To use
                        multiple separate headers by comma. Your headers need
                        to be exact(IE: Set-Cookie=a345ddsswe,X-Forwarded-
                        For:127.0.0.1) (*default=None)
  --proxy PROXY         Provide a proxy to run behind in the format
                        type://address:port (IE socks5://10.54.127.4:1080)
                        (*default=None)
  --tor                 Use Tor as the proxy to run behind, must have Tor
                        installed (*default=False)
  --check-tor           Check your Tor connection (default=False)
  -p PAYLOADS, --payloads PAYLOADS
                        Provide your own payloads separated by a comma IE AND
                        1=1,AND 2=2
  --pl PAYLOAD-LIST-PATH
                        Provide a file containing a list of payloads 1 per
                        line
  --force-ssl           Force the assignment of HTTPS instead of HTTP while
                        processing (*default=HTTP unless otherwise specified
                        by URL)
  --throttle THROTTLE-TIME (seconds)
                        Provide a sleep time per request (*default=0)
  --timeout TIMEOUT     Control the timeout time of the requests (*default=15)
  -P, --post            Send a POST request (*default=GET)
  -D POST-STRING, --data POST-STRING
                        Send this data with the POST request (*default=random)
  -t threaded, --threads threaded
                        Send requests in parallel (specify number of threads
                        (*default=1)
  -tP CONFIGTORPORT, --tor-port CONFIGTORPORT
                        Change the port that Tor runs on (*default=9050)
  -T, --test            Test the connection to the website before starting
                        (*default=True)

encoding options:
  arguments that control the encoding of payloads

  -e PAYLOAD [TAMPER-SCRIPT-LOAD-PATH ...], --encode PAYLOAD [TAMPER-SCRIPT-LOAD-PATH ...]
                        Encode a provided payload using provided tamper
                        script(s) you are able to payy multiple tamper script
                        load paths to this argument and the payload will be
                        tampered as requested
  -el PATH TAMPER-SCRIPT-LOAD-PATH, --encode-list PATH TAMPER-SCRIPT-LOAD-PATH
                        Encode a file containing payloads (one per line) by
                        passing the path and load path, files can only encoded
                        using a single tamper script load path

output options:
  arguments that control how WhatWaf handles output

  -F, --format          Format the output into a dict and display it
  -J, --json            Send the output to a JSON file
  -Y, --yaml            Send the output to a YAML file
  -C, --csv             Send the output to a CSV file
  --fingerprint         Save all fingerprints for further investigation
  --tamper-int INT      Control the amount of tampers that are displayed
                        (*default=5)
  --traffic FILENAME    store all HTTP traffic headers into a file of your
                        choice
  --force-file          Force the creation of a file even if there is no
                        protection identified
  -o DIR, --output DIR  Save a copy of the file to an arbitrary directory

database arguments:
  arguments that pertain to Whatwafs database

  -c, --url-cache       Check against URL's that have already been cached into
                        the database before running them saves some time on
                        scanning multiple (*default=False)
  -uC, --view-url-cache
                        Display all the URL cache inside of the database, this
                        includes the netlock, tamper scripts, webserver, and
                        identified protections
  -pC, --payload-cache  View all payloads that have been cached inside of the
                        database
  -vC, --view-cache     View all the cache in the database, everything from
                        URLs to payloads
  --export FILE-TYPE    Export the already encoded payloads to a specified
                        file type and save them under the home directory

misc arguments:
  arguments that don't fit in any other category

  --verbose             Run in verbose mode (more output)
  --hide                Hide the banner during the run
  --update              Update WhatWaf to the newest development version
  --save FILENAME       Save the encoded payloads into a file
  --skip                Skip checking for bypasses and just identify the
                        firewall
  --verify-num INT      Change the request amount to verify if there really is
                        not a WAF present(*default=5)
  -W, --determine-webserver
                        Attempt to determine what web server is running on the
                        backend (IE Apache, Nginx, etc.. *default=False)
  --wafs                Output a list of possible firewalls that can be
                        detected by WhatWaf
  --tampers             Output a list of tamper script load paths with their
                        description
  -M, --mine            Pass this flag to mine XMR for you and the whatwaf
                        development team

```
