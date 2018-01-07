# WhatWaf?

WhatWaf is an advanced firewall detection tool who's goal is to give you the idea of "There's a WAF?". WhatWaf works by detecting a firewall on a web application, and attempting to detect a bypass (or two) for said firewall, on the specified target.

# Features
 - Ability to run on a single URL with the `-u/--url` flag
 - Ability to run through a list of URL's with the `-l/--list` flag
 - Ability to detect over 40 different firewalls
 - Ability to try over 20 different tampering techniques
 - Ability to pass your own payloads either from a file, from the terminal, or use the default payloads
 - Default payloads that are guaranteed to produce at least one WAF triggering
 - Ability to bypass firewalls using both SQLi techniques and cross site scripting techniques
 - Ability to run behind multiple proxy types (`socks4`, `socks5`, `http`, `https` and `Tor`)
 - Ability to use a random user agent, personal user agent, or custom default user agent
 - Auto assign protocol to HTTP or ability to force protocol to HTTPS
 - A built in encoder so you can encode your payloads into the discovered bypasses
 - More to come...

# Installation

Installing whatwaf is super easy, whatwaf is compatible with Python2 and Python3, all you have to do is the following:

```
sudo -s << EOF
git clone https://github.com/ekultek/whatwaf.git
cd whatwaf
chmod +x whatwaf.py
pip install -r requirements.txt
./whatwaf.py --help
EOF
```

# Proof of concept

First we'll run the website through WhatWaf and figure out which firewall protects it (if any):
![item1](http://i67.tinypic.com/142y9s6.png)

Next we'll go to that website and see what the page looks like:
![item2](http://i64.tinypic.com/262mjhl.png)

Hmm.. that doesn't really look like Cloudflare does it? Lets see what the headers say:
![item4](http://i66.tinypic.com/5txx5x.png)

And finally, lets try one of the bypasses that it tells us to try:
![item3](http://i66.tinypic.com/sdi3x0.png)

# Demo video

[![to_video](http://i67.tinypic.com/2daawow.png)](https://vimeo.com/247623511)

# Get involved!

If you want to make some tamper scripts, want to add some functionality or just want to make something look better. Getting involved is easy:

 1. Fork the repository
 2. Edit the code to your liking
 3. Send a pull request

I'm always looking for some helpful people out there, and would love help with this little side project I got going on, Thanks! 
