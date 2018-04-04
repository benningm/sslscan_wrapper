[![Gem Version](https://badge.fury.io/rb/sslscan_wrapper.svg)](https://badge.fury.io/rb/sslscan_wrapper)

# sslscan\_wrapper

sslscan\_wrapper is a wrapper around the sslscan tool to scan SSL/TLS protocol parameters.

 * [rbsec/sslscan at GitHub](https://github.com/rbsec/sslscan)

Since it is only a wrapper around sslscan it does not depend on the openssl version
the ruby interpreter is linked with. The sslscan tool can be compiled statically with
a openssl version supporting old protocol versions and ciphers.

## API Documentation

Available at [rubydoc.info](http://www.rubydoc.info/gems/sslscan_wrapper).

## Usage

```
require 'sslscan_wrapper'

scanner = SslscanWrapper::Scanner.new
report = scanner.scan('www.somesite.tld', 443)

report.ciphers
# => ["ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-RSA-AES128-GCM-SHA256", ...
report.host
# => "www.somesite.tld"
report.signature_algorithm
# => "sha256WithRSAEncryption"
report.heartbleed_vulnerable?
# => false
```

