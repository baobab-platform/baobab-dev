---
title: Environment Variables
description: Discover the environment variables used by the BAOBAB build and helper scripts.
---

# Environment Variables

The BAOBAB Development Container uses environment variables to establish a consistent runtime environment for developers and the tools running inside the container.

These variables configure language runtimes, development tools, helper utilities, and container metadata without requiring manual setup by individual developers.

Where possible, the environment is configured once during image creation so that every development session begins from the same predictable baseline.

---

## Philosophy

Environment variables are used to configure **runtime behavior**, not software versions.

The project deliberately separates these responsibilities:

* **Version management** determines what software is installed.
* **Build arguments** influence how the image is built.
* **Environment variables** configure how installed software behaves at runtime.

This separation improves clarity and keeps each configuration mechanism focused on a single responsibility.

---

## BAOBAB Environment Variables

The development container exposes several BAOBAB-specific variables that provide metadata about the running environment.

Typical examples include:

| Variable               | Purpose                                       |
| ---------------------- | --------------------------------------------- |
| `BAOBAB_CONFIG_DIR`    | Location of shared BAOBAB configuration files |
| `BAOBAB_IMAGE_VERSION` | Published image version                       |
| `BAOBAB_BUILD_DATE`    | Image build timestamp                         |
| `BAOBAB_GIT_REVISION`  | Source revision used to build the image       |

These variables improve traceability and allow helper utilities to identify the running environment.

---

## Python Environment

The container configures Python to provide a predictable and reproducible development experience.

Typical configuration includes:

| Variable                                | Purpose                                            |
| --------------------------------------- | -------------------------------------------------- |
| `PYTHONUNBUFFERED`                      | Ensures immediate console output                   |
| `PYTHONDONTWRITEBYTECODE`               | Prevents unnecessary `.pyc` file generation        |
| `PIP_DISABLE_PIP_VERSION_CHECK`         | Disables version check during package installation |
| `PIP_NO_CACHE_DIR` *(where applicable)* | Controls package cache behavior                    |

These settings reduce unnecessary output, simplify container behavior, and improve consistency during development and automation.

---

## Poetry Configuration

Poetry is preconfigured to encourage isolated, project-local virtual environments.

Typical variables include:

| Variable                        | Purpose                                                   |
| ------------------------------- | --------------------------------------------------------- |
| `POETRY_VIRTUALENVS_IN_PROJECT` | Creates virtual environments inside the project directory |
| `POETRY_NO_INTERACTION`         | Disables interactive prompts during automation            |

Using project-local virtual environments makes dependencies easier to manage and ensures each project remains self-contained.

---

## Node / Corepack Configuration

Node.js, npm, pnpm, and yarn are all provisioned during image creation (Dockerfile `with-node` stage) rather than left for a developer or a container-startup command to install.

Typical configuration includes:

| Variable                     | Purpose                                                                                                                                                                                                                                                                                                        |
| ----------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `COREPACK_ENABLE_NETWORK=0`   | Prevents Corepack from making any network request to fetch a package-manager release. This image already bakes in the exact pnpm version consuming repos currently declare (`corepack prepare "pnpm@${PNPM_VERSION}" --activate`), so no fetch should ever be needed; if a consumer's own `package.json` `packageManager` pin later drifts ahead of this image's own pin, Corepack fails immediately with a clear error naming the missing version instead of silently downloading it — or, without this variable, prompting for interactive confirmation and hanging in a non-TTY Codespace/Dev Container lifecycle command. See `docs/architecture/version-management.md § Consumer Version Coupling` and `docs/incidents/2026-09-18-codespaces-corepack-interactive-prompt.md`. |

Consumer repos should **not** need to run `corepack enable` themselves in a `postCreateCommand`/`updateContentCommand` — it is a filesystem change (installing shim scripts) already baked into the image at build time.

---

## Flutter Environment

The Flutter SDK is configured during image creation so it is immediately available.

Typical configuration includes:

| Variable                      | Purpose                                   |
| ----------------------------- | ----------------------------------------- |
| `FLUTTER_HOME` *(if defined)* | Flutter SDK installation directory        |
| `PATH`                        | Includes the Flutter and Dart executables |

This eliminates additional setup steps after the container has been created.

---

## PATH Configuration

The container extends the system `PATH` to make installed tools available without additional configuration.

Directories typically included are:

* System binaries
* User-local executables
* Flutter SDK binaries
* Dart SDK binaries
* BAOBAB helper utilities

As a result, commonly used commands such as:

```text id="x4txek"
python
poetry
uv
node
npm
flutter
docker
gh
baobab-summary
```

are immediately available from any shell session.

---

## Locale and Timezone

The container establishes consistent locale and timezone settings.

Typical configuration includes:

| Variable                   | Purpose                     |
| -------------------------- | --------------------------- |
| `LANG`                     | Default language and locale |
| `LC_ALL` *(if configured)* | Locale consistency          |
| `TZ`                       | Default timezone            |

Using standardized locale settings ensures consistent behavior across development environments, particularly for sorting, formatting, and Unicode handling.

---

## Runtime Metadata

Several variables describe the running image rather than configuring software behavior.

These values may be consumed by:

* helper utilities;
* diagnostics;
* build verification;
* automation scripts;
* support tooling.

Embedding runtime metadata simplifies troubleshooting by allowing developers to identify the exact environment in use.

---

## Using Environment Variables

Developers can inspect the current environment using standard shell commands.

For example:

```bash id="tnhpx8"
printenv
```

To inspect a specific variable:

```bash id="r72zsm"
echo "$BAOBAB_IMAGE_VERSION"
```

or

```bash id="8mtolx"
echo "$POETRY_VIRTUALENVS_IN_PROJECT"
```

These commands are useful when troubleshooting configuration or verifying the runtime environment.

---

## Custom Environment Variables

Projects may define additional environment variables as required.

Examples include:

* application configuration;
* API endpoints;
* feature flags;
* development secrets;
* testing configuration.

Project-specific variables should remain within the project configuration rather than being added to the shared development image unless they are universally applicable to all BAOBAB projects.

This keeps the base image generic and reusable.

---

## Best Practices

When working with environment variables:

* Use them to configure runtime behavior rather than software versions.
* Avoid embedding sensitive information into the image.
* Keep project-specific configuration within the project.
* Prefer explicit, documented variables over implicit defaults.
* Document new shared variables alongside their intended purpose.

These practices promote transparency, maintainability, and consistent behavior across development environments.

---

## Summary

Environment variables provide the runtime configuration that transforms the BAOBAB Development Container from a collection of installed tools into a cohesive development environment. By configuring language runtimes, development utilities, helper commands, and runtime metadata in a consistent and centralized manner, the project ensures that every developer begins with the same predictable environment while maintaining a clear separation between configuration, infrastructure, and version management.
