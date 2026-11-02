---
title: Usage Guide
description: Get started with the BAOBAB development container in local, cloud, and editor-based workflows.
---

# Usage

The BAOBAB development container is designed to work consistently across local Docker environments, GitHub Codespaces, and VS Code Dev Containers.

<div class="doc-intro">
<p>Choose the workflow that matches your environment and follow the recommended setup path.</p>
</div>

<div class="doc-grid">
<div class="doc-card">
<div class="doc-card-icon"><span class="twemoji">{% include ".icons/material/laptop.svg" %}</span></div>
### [Running Locally](running-locally.md)
Set up the container on your workstation with Docker and the required prerequisites.
</div>

<div class="doc-card">
<div class="doc-card-icon"><span class="twemoji">{% include ".icons/material/cloud.svg" %}</span></div>
### [GitHub Codespaces](github-codespaces.md)
Launch the same development environment in the cloud with minimal setup.
</div>

<div class="doc-card">
<div class="doc-card-icon"><span class="twemoji">{% include ".icons/material/microsoft-visual-studio-code.svg" %}</span></div>
### [VS Code Dev Containers](vscode-devcontainers.md)
Use VS Code’s remote development experience with the BAOBAB toolchain.
</div>
</div>


## Maintaining the developer toolchain

For a change to Python, Node, pnpm, Playwright, Docker, PostgreSQL client, Go,
Java, Rust or bundled CLI dependencies, start with the
[Toolchain Upgrade Playbook](toolchain-upgrade-playbook.md). It includes the
cross-repository compatibility review, frozen installation, embedded dependency
checks, eight-image CI matrix, release/rollback and evidence checklist.

Read the [DEV-10/DEV-14 lessons learned](../incidents/2026-10-30-dev10-dev14-toolchain-retrospective.md)
for the actual 2026 failures and verified controls. The older
[GHCR manifest](../incidents/2026-09-13-ghcr-v1.3.0-frontend-manifest-loss.md)
and [Corepack/Playwright](../incidents/2026-09-18-codespaces-corepack-interactive-prompt.md)
incidents remain separate primary records.
