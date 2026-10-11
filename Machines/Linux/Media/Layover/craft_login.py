#!/usr/bin/env python3
"""Authenticate to Craft CMS and refresh the cookie jar used by layover_rce.py.

Usage: craft_login.py <loginName> [jar_path]
The password is entered interactively and is not stored in this script.
"""
import getpass
import http.cookiejar
import re
import sys
import urllib.parse
import urllib.request

BASE = "http://portal.international.htb"


def find_csrf(html):
    for pat in (
        r'csrfTokenValue":"([^"]+)',
        r'name="CRAFT_CSRF_TOKEN"\s+value="([^"]+)"',
        r'csrfTokenValue\s*=\s*"([^"]+)"',
    ):
        m = re.search(pat, html)
        if m:
            return m.group(1)
    return None


def main():
    if len(sys.argv) < 2:
        raise SystemExit("usage: craft_login.py <loginName> [jar]")
    login_name = sys.argv[1]
    password = getpass.getpass("Craft password: ")
    jar_path = sys.argv[2] if len(sys.argv) > 2 else "/tmp/cj"

    jar = http.cookiejar.MozillaCookieJar(jar_path)
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

    html = opener.open(BASE + "/admin/login", timeout=20).read().decode(errors="replace")
    token = find_csrf(html)
    if not token:
        raise SystemExit("no CSRF token on login page")

    data = urllib.parse.urlencode({
        "loginName": login_name,
        "password": password,
        "CRAFT_CSRF_TOKEN": token,
        "rememberMe": "1",
    }).encode()
    req = urllib.request.Request(
        BASE + "/admin/actions/users/login",
        data=data,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "X-Requested-With": "XMLHttpRequest",
            "X-CSRF-Token": token,
        },
    )
    try:
        r = opener.open(req, timeout=25)
        sys.stderr.write("login HTTP %s\n%s\n" % (r.status, r.read(400).decode(errors="replace")))
    except urllib.error.HTTPError as e:
        sys.stderr.write("login HTTPERR %s\n%s\n" % (e.code, e.read(400).decode(errors="replace")))
        raise SystemExit(1)

    d = opener.open(BASE + "/admin/dashboard", timeout=20)
    body = d.read().decode(errors="replace")
    ok = ("csrfTokenValue" in body) and ("/admin/login" not in d.geturl())
    sys.stderr.write("dashboard %s url=%s authed=%s\n" % (d.status, d.geturl(), ok))

    jar.save(ignore_discard=True, ignore_expires=True)
    sys.stderr.write("saved cookies to %s\n" % jar_path)
    print("AUTHED" if ok else "NOT_AUTHED")


if __name__ == "__main__":
    main()
