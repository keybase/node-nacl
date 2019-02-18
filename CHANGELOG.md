# v1.1.0 (2019-02-18)

- Use a regular `require("sodium")` rather than indirection. We used to do indirection so that browserify would not include sodium, but that same technique breaks webpack.
- This is a breaking change since now you need to `browserify -i sodium` on all downstream dependencies. 

# v1.0.11 (2019-02-01)

- module updates
- use Buffer.from, not new Buffer


# v1.0.10 (2016-11-02)

- Expose Curve25519 scalar multiplication (via @zapu's PR #4)
