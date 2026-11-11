# Ingress Enforcer

`ingress-enforcer` uses nftables rules to ensure that traffic arriving on an interface can only reach prefixes that were advertised over that interface to an eBGP peer.

## Example Usage

This program is designed to be started after Bird, so use a Systemd unit or equivilent.

Usage is as follows

```
ingress-enforcer --peer <bird_protocol_name> [--peer ...]
```

It needs root (or `CAP_NET_ADMIN`) and Bird's control socket, which defaults to `/run/bird/bird.ctl`.

## Contributions

This repository is a public push-mirror of a segment of my personal projects monorepo. As such, pull requests are not accepted here.

If you would like to contribute a patch, please email me at the address on [my website](https://ewpratten.com).

