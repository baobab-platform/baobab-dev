# Development risk review for linux-libc-dev 7.0.0-44.44

## Evidence and scope

The Foundation scan and all eight Publish scans at PR head
`6c285e49a37beebb4a9dcade2f1d3ff9351ad957` found 30 advisories for
`linux-libc-dev=7.0.0-44.44` (27 HIGH, three CRITICAL). The results came from
merge checkout `ae0832986cd4d2a087586b63941de79575427df9`. The
[scan evidence](dev10-pr74-6c285e4-scan-evidence.json) records the exact
inventory and verified artifact hashes. All 30 findings block qualification.

Each record covers `final`, `infra`, `frontend` and `frontend-e2e` on
linux/amd64 and linux/arm64. The [source register](dev10-ubuntu-44.44-binary-applicability.json)
records both architecture DEB hashes, all eight matching installed-file
manifests, pinned Linux CNA records, the exact Ubuntu source paths and the
upstream fix candidates. Canonical's pinned CVE tracker gives generic Resolute
`linux` status `needed` for all 30.

The earlier Canonical OSV revision `e0002e1e7efd69cfd765691383b0c2b704bf682d`
explicitly names the binary version for the 23 **binary** findings and records
source-only evidence for the five **source** findings. The two **tracker**
rows below use the refreshed Resolute tracker and exact-tag source checks.
The package ships headers and documentation. Downstream software can use
those headers to call host kernel interfaces. Evidence of the effective host
kernel, device and mount controls is required for each covered use case.

The standard workspace runs as a non-root user but exposes the host Docker daemon and requests unconfined seccomp. Neither setting bounds what daemon-launched workloads can reach. Native smoke tests establish runtime functionality. The table identifies controls that an operator would need to verify before relying on them. Across the rows, confidence in actual host reachability is limited by missing host, mount, capability and consumer receipts. [Workspace configuration](../../.devcontainer/devcontainer.json)

## Findings and proposed treatment

**Candidate** marks one of three findings identified during the earlier
conditional review. **Hold** requires remediation or evidence of an effective
control. **Priority hold** marks a CRITICAL finding requiring host evidence.
All three labels carry a blocking disposition in the current inventory.

| Finding | Severity and OSV scope | Development exposure and plausible impact | Control, limits and evidence required | Proposed treatment |
|---|---|---|---|---|
| [CVE-2022-50240](https://ubuntu.com/security/CVE-2022-50240) | HIGH · source | Binder mappings on a host exposing an Android Binder device can leave a stale kernel mapping pointer. A consumer may compile Binder ioctls from the headers. | Exclude Binder devices from the workspace and daemon-created containers. Check the effective device inventory. The recorded fix is an ancestor and the named files are unchanged. | Candidate |
| [CVE-2025-40190](https://ubuntu.com/security/CVE-2025-40190) | HIGH · source | An ext4 filesystem with corrupt extended-attribute inode metadata can damage reference accounting when attributes are updated. A mounted host volume can expose the path to ordinary file operations. | Use managed development volumes and exclude untrusted filesystem images. Verify backing storage and the host kernel. The recorded fix is an ancestor with unchanged named source. | Candidate |
| [CVE-2026-100081](https://ubuntu.com/security/CVE-2026-100081) | HIGH · binary | Xen backend disconnect during network processing can leave stale multicast state and disrupt the backend host. The backend runs outside the userspace image. | Obtain host or provider evidence of patched xen-netback or absence of that backend. Network namespace isolation does not establish backend isolation. | Hold |
| [CVE-2026-68103](https://ubuntu.com/security/CVE-2026-68103) | HIGH · source | A process with access to an AMD GPU render device can create conflicting queue doorbell mappings, disrupting GPU queue handling. | Check device passthrough and daemon access on the actual runner. Require isolation or updated amdgpu on GPU-enabled hosts. | Hold |
| [CVE-2026-72198](https://ubuntu.com/security/CVE-2026-72198) | HIGH · source | Classic NTFS parsing of malformed attribute records can misinterpret filesystem metadata. Downstream tools can access already-mounted filesystems. | Exclude untrusted NTFS media and verify the host driver. The tagged source lacks the named file and three upstream commits remove it. Mounted-volume exposure still depends on the host. | Candidate |
| [CVE-2026-74578](https://ubuntu.com/security/CVE-2026-74578) | HIGH · source | Concurrent kernel AF_ALG cipher operations can compromise confidentiality of data processed on a susceptible host. A developer program can use that socket interface. | Verify host kernel fix or an enforced AF_ALG restriction. Post-fix source-file matches strengthen the Ubuntu source case, while runtime socket reachability is unmeasured. | Hold |
| [CVE-2026-89805](https://ubuntu.com/security/CVE-2026-89805) | HIGH · binary | GPU memory migration under pressure can access released memory in the host DRM subsystem. This concerns workloads using mapped GPU memory. | Verify effective render-device and daemon restrictions, or qualify a fixed GPU host. Lack of a GPU in the image manifest cannot establish isolation. | Hold |
| [CVE-2026-98376](https://ubuntu.com/security/CVE-2026-98376) | HIGH · binary | An accessible BPF map-management interface can expose an out-of-bounds kernel lookup during inner-map replacement. | Verify host BPF permissions, unprivileged BPF settings and daemon-created container capabilities. A compile-time BPF interface is present. | Hold |
| [CVE-2026-98420](https://ubuntu.com/security/CVE-2026-98420) | HIGH · binary | A host running ksmbd may expire valid sessions or consume resources during session setup. Development shares could become unavailable. | Confirm host SMB server state and inbound access controls. Include sibling containers started through the host daemon. | Hold |
| [CVE-2026-98869](https://ubuntu.com/security/CVE-2026-98869) | HIGH · binary | The advisory describes incorrect BPF verifier zero-extension on s390. Native amd64/arm64 qualification narrows that architecture-specific path. Cross-built BPF programs can still be deployed elsewhere. | Constrain evaluation to native targets and verify consumer deployment architectures and host BPF policy before proposing an exception. | Hold |
| [CVE-2026-98890](https://ubuntu.com/security/CVE-2026-98890) | HIGH · binary | A host using the Libertas Wi-Fi driver in monitor mode can read beyond a transmitted frame. Hardware and mode access matter. | Check wireless device assignment and host driver state. Historical patch-ID evidence needs semantic review against the current source. | Hold |
| [CVE-2026-99239](https://ubuntu.com/security/CVE-2026-99239) | HIGH · binary | Concurrent L2CAP socket operations can corrupt Bluetooth channel state. Software may reach the host stack if Bluetooth sockets are allowed. | Verify Bluetooth socket restrictions and actual host support, including daemon-launched workloads. Device inventory alone is insufficient. | Hold |
| [CVE-2026-99260](https://ubuntu.com/security/CVE-2026-99260) | HIGH · binary | A writable NTFS filesystem using the named driver may mishandle resident attributes when changing sparse or compressed flags. | Identify the actual driver on any mounted NTFS volumes. Enforce a supported host fix or exclude these volumes and raw mounting privileges. | Hold |
| [CVE-2026-99270](https://ubuntu.com/security/CVE-2026-99270) | HIGH · binary | TCP connection migration on a susceptible host can leave a kernel timer referencing released memory. Ordinary networking can exercise the TCP subsystem. | Require host kernel remediation evidence. Non-root operation and private forwarded ports leave outbound and local TCP available. | Hold |
| [CVE-2026-99272](https://ubuntu.com/security/CVE-2026-99272) | HIGH · binary | A kernel SMB client reading from an untrusted server can read beyond a reply buffer, exposing host memory or destabilizing the client. | Inventory backing mounts, restrict SMB peers and verify the host client fix. Reading a bind-mounted share can reach the kernel client. | Hold |
| [CVE-2026-99274](https://ubuntu.com/security/CVE-2026-99274) | HIGH · binary | Querying file extent information on a kernel SMB mount can lead to invalid reads or lost progress with a malformed server reply. | Verify SMB mount sources and host patch level. Restricting mount creation inside the container leaves existing mounts accessible. | Hold |
| [CVE-2026-99275](https://ubuntu.com/security/CVE-2026-99275) | HIGH · binary | A kernel SMB client negotiating a session with an untrusted server can disclose kernel memory during authentication. | Require verified SMB endpoints and a patched host client. An image package inventory cannot attest to peer trust. | Hold |
| [CVE-2026-99282](https://ubuntu.com/security/CVE-2026-99282) | HIGH · binary | Traffic on a host using the TEQL queuing discipline can exercise a packet lifetime fault, with consequences for host availability. | Verify the host qdisc configuration and restrict network administration and daemon access. Application traffic can use an existing qdisc. | Hold |
| [CVE-2026-99287](https://ubuntu.com/security/CVE-2026-99287) | CRITICAL · binary | Xen network backend ring cleanup on connection failure can unmap shared ring state twice. A susceptible Xen backend serving a guest is the relevant execution context. Backend failure can interrupt other guests. | Require a provider or host attestation identifying a patched backend or a non-Xen execution boundary, including nested and daemon-provisioned workloads. The image headers cannot establish the hypervisor state. | Priority hold |
| [CVE-2026-99288](https://ubuntu.com/security/CVE-2026-99288) | HIGH · binary | Concurrent TCP socket lookups on a vulnerable host can access a recycled socket and crash the kernel. Ordinary TCP services share this dependency. | Require an independently verified host kernel fix. Container non-root and namespace separation do not remove the shared TCP implementation. | Hold |
| [CVE-2026-99290](https://ubuntu.com/security/CVE-2026-99290) | HIGH · binary | Concurrent durable reconnects to a susceptible ksmbd server can leave a stale file handle and corrupt host kernel memory. | Verify host SMB server configuration and patch level, including reachable development shares. Limit inbound access pending remediation. | Hold |
| [CVE-2026-99292](https://ubuntu.com/security/CVE-2026-99292) | HIGH · binary | Permission or ownership updates on a kernel SMB mount can overwrite kernel memory while translating remote access-control data. | Verify backing mounts and host client patches. Use controlled storage, accounting for shares mounted outside the workspace. | Hold |
| [CVE-2026-99295](https://ubuntu.com/security/CVE-2026-99295) | HIGH · binary | A receive failure on a kernel SMB mount can leave the client using freed request state, risking host instability. | Require host client remediation or exclude SMB-backed workspaces. Restricting remote peers alone cannot prevent connection errors. | Hold |
| [CVE-2026-99302](https://ubuntu.com/security/CVE-2026-99302) | HIGH · binary | A host exposing an NVMe-over-RDMA target may read beyond connection data received from a peer. | Verify the target service, assigned RDMA devices and network reachability. Exclude untrusted peers and require host patch evidence for enabled targets. | Hold |
| [CVE-2026-99304](https://ubuntu.com/security/CVE-2026-99304) | HIGH · binary | A kernel CephFS client processing snapshot metadata from a faulty or compromised metadata server can read beyond the supplied message. | Inventory CephFS-backed mounts and peers. Verify host client patches and server trust. A bind mount may already use CephFS. | Hold |
| [CVE-2026-99306](https://ubuntu.com/security/CVE-2026-99306) | CRITICAL · binary | The host CephFS client processes metadata-server maps from a monitor. An invalid rank range can cause out-of-bounds stack access. A malicious or compromised monitor is a relevant precondition, with greater exposure on a legacy unauthenticated connection. | Require evidence of the host client fix or exclusion of CephFS backing mounts and client access. Verify authenticated monitor transport if Ceph is used. Authentication alone cannot protect against a compromised trusted monitor. | Priority hold |
| [CVE-2026-99310](https://ubuntu.com/security/CVE-2026-99310) | CRITICAL · binary | A host NFSv4 server processing concurrent client state transitions can read freed state during an identity exchange. A reachable susceptible server and active client state are relevant. Service failure or kernel memory corruption can affect other users. | Verify the host and daemon-created workloads expose no susceptible NFS server, or supply host patch and export evidence. Restrict server access pending remediation. Client-side headers and non-root runtime do not qualify server state. | Priority hold |
| [CVE-2026-99311](https://ubuntu.com/security/CVE-2026-99311) | HIGH · binary | Following a symlink on a malformed UDF filesystem can crash a susceptible host kernel. Developers may encounter this when inspecting disk images. | Exclude untrusted UDF mounts and raw device access, including daemon mounts, or verify the backing host fix. | Hold |
| [CVE-2026-99312](https://ubuntu.com/security/CVE-2026-99312) | HIGH · tracker | A susceptible x86 KVM host can retain stale memory-management state while servicing nested virtualisation. The ABI header is present on both image architectures. The exact Ubuntu tag contains the x86 implementation and matches the upstream pre-fix context. | Verify a patched host or enforce and attest exclusion of KVM device access and nested virtualisation across workspaces and daemon-launched containers. ARM64 image builds alone leave x86 downstream targets unqualified. | Hold |
| [CVE-2026-99317](https://ubuntu.com/security/CVE-2026-99317) | HIGH · tracker | A susceptible ALSA host can race concurrent DSP load operations through an accessible hardware-dependent sound device. Both images export the ALSA userspace ABI. The exact Ubuntu tag contains the implementation and matches the upstream pre-fix context. | Verify the host fix or attest exclusion of ALSA hardware-dependent devices, including device access granted by the Docker daemon. A header-only package and non-root workspace do not establish host isolation. | Hold |

## Evidence required before a decision

The earlier technical review identified **CVE-2022-50240, CVE-2025-40190 and
CVE-2026-72198** for conditional consideration. Their source witnesses remain
available for [Binder](https://github.com/gregkh/linux/commit/a43cfc87caaf46710c8027a8c23b8a55f1078f19),
[ext4](https://github.com/gregkh/linux/commit/57295e835408d8d425bef58da5253465db3d6888)
and [classic NTFS](https://github.com/gregkh/linux/commit/7ffa8f3d30236e0ab897c30bdb01224ff1fe1c89).
Effective device restrictions, mount provenance and host patch evidence for
the actual workspaces and daemon-launched workloads remain unverified.

### Hosted reference workspace observations

The [development host evidence workflow](../../.github/workflows/dev10-development-host-evidence.yml)
launches this repository's digest-pinned reference devcontainer on native
GitHub-hosted amd64 and arm64 VMs. It captures the running kernel, relevant
kernel config, device visibility and discretionary permissions, effective
capabilities and seccomp, backing filesystem types, and daemon observations.
When the workspace starts an ordinary child through its Docker socket, the
receipt records that child's runtime and compares it with the host.

The probe reads metadata and runs the reference startup with onboarding
lifecycle commands skipped. Evidence applies to the tested VMs and their
workspaces. A device absent from an observed namespace does not establish
an enforced restriction. A backing filesystem type does not identify who
controls its contents. The host kernel identity must be checked against
applicable vendor fixes before qualifying a patched host. Codespaces and
workstations each need evidence from their actual runtime boundary.

The accountable owner's conditional concurrence was recorded against the
earlier 28-finding scope and head `513d53d`. The last formal security review
requested changes on `3fe034776ae1`. None of the 32 formal reviews inspected
was on `6c285e49`. [Owner concurrence](https://github.com/baobab-platform/baobab-dev/pull/74#issuecomment-7056442669)
· [Security review](https://github.com/baobab-platform/baobab-dev/pull/74#pullrequestreview-5997778838)

The verified signed archive contains no supported package with fixes for
this inventory. All 30 findings remain under investigation. The 27 holds and
the missing host evidence for the three historical candidates prevent
freezing an approval-ready residual inventory. Both signed Updates indexes
list `linux-libc-dev` as a dependency of `libc6-dev=2.43-2ubuntu2.7`.

Once the remaining findings have supported dispositions and the proposed
scope is frozen, the decision needs attributable owner concurrence,
independent approval on the exact decision head, merged custody verification
and exact-byte activation. Full qualification follows an effective
decision or clean remediation scans. [Governance contract](../adr/ADR-DEV10-001-reusable-development-risk-policy.md)
