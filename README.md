# Scan for DNS over TLS Nameservers
NOTE: DNSSEC works wonders when it comes to countering DNS spoofing attacks.
However, there is some controversy around how DNSSEC is designed. I won't go
into the details of political nature of DNSSEC here, but the project will
forever remain political as it has started that way.

As the adoption of DNSSEC and DANE is met with challenges, the future of
securing DNS traffic on the internet remains unknown. Another alternative
solution to the problem that is being tried is DNS over TLS(DoT).

Securing the DNS is work in progress. As with DNSSEC, in order to make a
recursive DNS server without DNSSEC, all the name servers involved in recursive
queries need to secure the traffic in one way or another:

```
Recursive DNS server -> Root NS -> TLD NS -> domain service NS / your self-hosted NS
```

This will provide people who are skeptical about DNSSEC with a better
alternative.

I made this python module to scan 853/TCP port on all TLD name servers.

## Run it yourself
- The module spawns 500 threads
- Around 500MB of memory is required
- Run with good internet connection so that SYN packets won't get rate limited

```sh
./get-root.zone
python -m scandotns | tee output.json
```

## Results
### Takeaways as of 2024
- Only one of 13 root name servers started experimental DoT service
- No TLD DNS service provider is serious about supporting DoT

At the end of the day, securing the last mile(user - RDNSS) is good enough to
cover the most of attack vectors. You're screwed anyway if an attacker can
successfully send crafted DNS packets to the RDNSS or the NS of your service
provider.

No one is stopping you from employing both DoT and DNSSEC if you're not bothered
by the political side of DNSSEC.

### 27th September 2024
Raw data: [results/2024-09-27/output.json](results/2024-09-27/output.json)

| Name Servers | Description | Organization | Certificate Verifiable |
| - | - | - | - |
| b.root-servers.net. b.ns.arpa. | root name server | [University of Southern California](https://b.root-servers.org/) | [CA provided](https://b.root-servers.org/research/tls.html) |
| estia.ics.forth.gr. gr-m.ics.forth.gr. gr-at.ics.forth.gr. grdns.ics.forth.gr. estia.ics.forth.gr. gr-at.ics.forth.gr. grdns.ics.forth.gr. estia.ics.forth.gr. | ccTLD .cy(Cyprus), .gr(Greece), .ελ(Greece alt) | [FORTH](https://forth.gr/) | CA not provided |
| ns.kg. ns2.kg. | ccTLD .kg(Kyrgyzstan) | [AsiaInfo](https://www.cctld.kg/en/about) | CA not provided |

The fact that neither of TLD organization has documentation on DoT probably
means that their open DoT port was unintentional.
