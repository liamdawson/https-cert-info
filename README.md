# https-cert-info

A command-line tool outputs a summary of the HTTPS certificate (or certificate chain) for a server

## Installation

### Cargo

```shell
cargo install https-cert-info
```

### Manual

Download the binary from the [latest release](https://github.com/liamdawson/https-cert-info/releases/latest), and place it somewhere on `$PATH`.

## Examples

```shell
$ https-cert-info google.com
Connecting to google.com:443 (took 122ms)
Performing handshake for google.com (took 458ms)

Subject     *.google.com (C=US, ST=California, L=Mountain View, O=Google LLC, CN=*.google.com)
Issued by   GTS CA 1O1 (C=US, O=Google Trust Services, CN=GTS CA 1O1)
Valid from  28 days ago (2020-08-26T08:08:49Z)
Expires in  55 days (2020-11-18T08:08:49Z)

Subject Alternative Names:
  *.google.com
  *.android.com
  *.appengine.google.com
  *.bdn.dev
  *.cloud.google.com
  *.crowdsource.google.com
  *.datacompute.google.com
  *.g.co
  *.gcp.gvt2.com
  *.gcpcdn.gvt1.com
    and 63 more.

# using SNI to request a different domain
$ https-cert-info google.com -d www.google.com
Connecting to google.com:443 (took 17ms)
Performing handshake for www.google.com (took 461ms)

Subject     www.google.com (C=US, ST=California, L=Mountain View, O=Google LLC, CN=www.google.com)
Issued by   GTS CA 1O1 (C=US, O=Google Trust Services, CN=GTS CA 1O1)
Valid from  28 days ago (2020-08-26T08:14:23Z)
Expires in  55 days (2020-11-18T08:14:23Z)

Subject Alternative Names:
  www.google.com
```

## License

MIT OR Apache-2.0
