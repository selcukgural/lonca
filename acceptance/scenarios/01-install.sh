# The binaries a release ships, and a daemon started from them.
source "$ACC_LIB"

criterion A01 "lonca and lonca-audit say the release's version"
ok lonca --version
[ "$OUT" = "lonca $ACC_VERSION" ] || fail "lonca --version"
ok lonca-audit --version
[ "$OUT" = "lonca-audit $ACC_VERSION" ] || fail "lonca-audit --version"

criterion A02 "a daemon starts in a fresh home and doctor passes in cooperative mode"
start_daemon
ok lonca doctor --json
has '"ok":true'
has '"mode":"cooperative"'
has '"name":"daemon","level":"pass","detail":"version '"$ACC_VERSION"','
has '"name":"socket","level":"pass"'
ok lonca doctor
has "Doctor summary \(lonca $ACC_VERSION\)"
