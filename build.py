#!/usr/bin/env python3
"""Build blocklist.txt from Zero Breach Toolkit's indicator sets.

usage: python -I build.py --toolkit PATH/TO/Zero-Breach-Toolkit [--out blocklist.txt]

Run `python scan/zero-breach-toolkit.py --update` in the toolkit first: this
reads its per-user indicator cache through the toolkit's own verified loader and its
bundled AdFection list. Only domains are kept; IPs and file hashes are not DNS.
"""

import argparse
import datetime
import os
import re
import sys

VALID = re.compile(r"(?=.{4,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}")
# A feed error listing one of these would break the internet for every subscriber.
NEVER_BLOCK = frozenset(
    """google.com googleapis.com gstatic.com youtube.com apple.com icloud.com microsoft.com live.com
    windowsupdate.com office.com amazon.com amazonaws.com cloudfront.net akamaihd.net akamaized.net
    cloudflare.com github.com githubusercontent.com facebook.com whatsapp.com instagram.com
    appspot.com firebaseio.com firebaseapp.com herokuapp.com azurewebsites.net""".split()
)


def collect(toolkit):
    scan = os.path.join(toolkit, "scan")
    if not os.path.isfile(os.path.join(scan, "zbtriage", "feeds.py")):
        sys.exit("not a Zero Breach Toolkit checkout: " + toolkit)
    sys.path.insert(0, scan)
    from zbtriage import feeds
    from zbtriage.iocs import TYPE_DOMAIN, load_any, shared_service_domain

    # cached_sets refuses any file whose SHA-256 no longer matches the manifest or the release pin.
    sets, status = feeds.cached_sets()
    if status["refused"] or status["missing"]:
        sys.exit(f"indicator cache not usable, run the toolkit's --update: {status['refused'] or status['missing']}")
    unpinned = [s["id"] for s in status["loaded"] if not s["pinned_for_this_release"]]
    if unpinned:
        sys.exit(f"feeds not at the toolkit's reviewed pins (rerun --update without --latest): {unpinned}")
    sets.append(load_any(os.path.join(toolkit, "iocs", "adfection_iocs.txt")))

    domains = set()
    for indicator_set in sets:
        for indicator in indicator_set.indicators:
            if indicator.type != TYPE_DOMAIN:
                continue
            domain = indicator.value.strip().lower().rstrip(".").removeprefix("*.")
            if domain in NEVER_BLOCK:
                print("skipped critical domain listed in a feed: " + domain, file=sys.stderr)
            # Shared hosts (cloud, shorteners) would block innocent sites for everyone.
            elif VALID.fullmatch(domain) and not shared_service_domain(domain):
                domains.add(domain)
    return domains, len(feeds.SOURCES) + 1


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--toolkit", required=True)
    parser.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "blocklist.txt"))
    args = parser.parse_args()
    domains, sources = collect(os.path.abspath(args.toolkit))
    if len(domains) < 1000:
        sys.exit(f"only {len(domains)} domains found; refusing to overwrite {args.out}")
    header = [
        "# Spyware and stalkerware DNS blocklist (Pi-hole / AdGuard Home / hosts-style domain list)",
        f"# Built {datetime.date.today().isoformat()} from {sources} indicator sets: Amnesty International,",
        "# Citizen Lab, MVT project, Echap and Zero Breach Toolkit's AdFection list. See README.md.",
        f"# {len(domains)} domains. Blocking reduces exposure; it does not detect or remove an infection.",
    ]
    pending = args.out + ".tmp"
    with open(pending, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(header + sorted(domains)) + "\n")
    os.replace(pending, args.out)
    print(f"wrote {len(domains)} domains to {args.out}")


if __name__ == "__main__":
    main()
