# spyware-dns-blocklist

A DNS blocklist of known mercenary spyware and stalkerware domains, for Pi-hole, AdGuard Home or any filter that takes one domain per line. About 6,700 domains from public research by Amnesty International, Citizen Lab, the MVT project and Echap.

Blocking these domains cuts off known delivery, tracking and command-and-control infrastructure for every device on your network. It does not detect or remove an infection. To check a device, use [Zero Breach Toolkit](https://github.com/interplains/Zero-Breach-Toolkit) or [MVT](https://docs.mvt.re/).

## Add it to Pi-hole

1. Open the Pi-hole admin page and go to **Lists** (Pi-hole v6) or **Group Management > Adlists** (v5).
2. Add this address as a blocklist:

   ```
   https://raw.githubusercontent.com/zero10bit/spyware-dns-blocklist/main/blocklist.txt
   ```

3. Update gravity: **Tools > Update Gravity**, or `pihole -g` on the box.

Pi-hole re-downloads the list on its weekly gravity run. Devices that use their own DNS (DNS-over-HTTPS in the browser, a VPN, a hard-coded resolver) skip Pi-hole and are not protected by it.

## What it blocks

- **Mercenary spyware:** NSO Group (Pegasus), Intellexa/Cytrox (Predator), Candiru (DevilsTongue), FinFisher, Cyberbit, QuaDream, RCS Lab, Wintego, NoviSpy, Operation Triangulation and others, as published by Amnesty International, Citizen Lab and the MVT project.
- **AdFection:** the ad-tech network Citizen Lab tied to Candiru spyware delivery.
- **Stalkerware:** commercial phone-monitoring apps, from Echap's list. This includes family-safety apps such as Life360, Qustodio, Bark and Kaspersky Safe Kids, which stop working for anyone on a network using this list. Allow those domains in Pi-hole if someone needs them.

Shared hosting and cloud domains that the source data flags (URL shorteners, cloud platforms) are left out, so a blocked entry never takes down unrelated sites. Entries on platforms such as `appspot.com` or `firebaseio.com` block one specific subdomain, not the platform.

Some domains come from older campaigns and may have lapsed or been re-registered since. If something you need is blocked, allow it in Pi-hole.

## Rebuilding

`build.py` regenerates `blocklist.txt` from a local [Zero Breach Toolkit](https://github.com/interplains/Zero-Breach-Toolkit) checkout, which downloads the source feeds at reviewed commits and checks their SHA-256:

```
python scan/zero-breach-toolkit.py --update        # in the toolkit
python -I build.py --toolkit PATH/TO/Zero-Breach-Toolkit
```

## Sources

- Amnesty International Security Lab, [AmnestyTech/investigations](https://github.com/AmnestyTech/investigations)
- The Citizen Lab, [citizenlab/malware-indicators](https://github.com/citizenlab/malware-indicators)
- MVT project, [mvt-project/mvt-indicators](https://github.com/mvt-project/mvt-indicators) (MIT)
- Echap, [AssoEchap/stalkerware-indicators](https://github.com/AssoEchap/stalkerware-indicators)
- Zero Breach Toolkit, [AdFection indicator set](https://github.com/interplains/Zero-Breach-Toolkit/tree/main/iocs) (CC0)

The domains are factual indicators gathered by these organisations; credit for the research is theirs. If you represent one of them and want your data removed, open an issue.
