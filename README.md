# NetScope

A lightweight, client-side network security toolkit. No backend required.

**[Live Demo](https://patrickking67.github.io/netscope/)**

## Features

- **IP & Geolocation** - Detect public IP, ISP, ASN, and map your approximate location
- **Speed Test** - Measure download, upload, and latency with animated gauges
- **Breach Check** - Check emails (via XposedOrNot) and passwords (via HIBP k-anonymity)
- **DNS & Security Scan** - Lookup DNS records, check SPF/DMARC/DKIM, DNSSEC, WebRTC leaks
- **Export** - Copy results, share via email, or download a PDF report

## Tech

Pure HTML, CSS, and JavaScript. No frameworks, no build step, no backend.

**Free APIs used:**
| Feature | API |
|---------|-----|
| IP Detection | [ipify](https://www.ipify.org/) |
| Geolocation | [ipapi.co](https://ipapi.co/) / [ipwho.is](https://ipwho.is/) |
| Password Breach | [HIBP Pwned Passwords](https://haveibeenpwned.com/API/v3#PwnedPasswords) |
| Email Breach | [XposedOrNot](https://xposedornot.com/) |
| DNS Lookup | [Google DNS-over-HTTPS](https://dns.google/) |
| Maps | [Leaflet](https://leafletjs.com/) + [OpenStreetMap](https://www.openstreetmap.org/) |
| Speed Test | [Cloudflare](https://speed.cloudflare.com/) |

## Privacy

- Passwords are SHA-1 hashed locally; only the first 5 hash characters are sent (k-anonymity)
- No analytics, tracking, or data storage
- All processing happens in your browser

## Development

```bash
# Clone
git clone https://github.com/patrickking67/netscope.git
cd netscope

# Serve locally
npx serve src
```

## License

[MIT](LICENSE)
