# Image Python dependency security


The final-image jobs in runs `40360334198` and `40360515417` failed on
CVE-2026-97687 / CVE-2026-97689 in urllib3 2.7.0, on both architectures.
`config/python-build-constraints.txt` now constrains image-tool dependency
resolution to urllib3 2.8.0 in both system pipx and Poetry's isolated environment.
The build checks dependency compatibility and reads back both installed versions;
a resolver conflict fails the build. This constraint is scoped to image creation
and does not override a consuming project's frozen dependency lock.

The original failed runs remain historical evidence. A source test or successful
install does not qualify the image: fresh final-head amd64/arm64 scans, all existing
required checks and developer-environment evidence remain required. No scan
exception or expiry was added or extended by this remediation. Do not release,
publish a new version or promote a consumer digest on the strength of this source
change. Roll back only to a previously qualified digest; an image with the original
finding is not a security rollback target.
