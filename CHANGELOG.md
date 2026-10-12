# Changelog

## Legacy releases

Versions up to and including 1.5.0 were released from
[schubergphilis/awsfindingsmanagerlib](https://github.com/schubergphilis/awsfindingsmanagerlib).
Version 2.0.0 is a complete rewrite with a different rules schema and Python API.
See [UPGRADING.md](UPGRADING.md) before upgrading from 1.x.

### 1.5.0 (2026-06-25)

* chore: update dependencies to latest and require Python >=3.10

### 1.4.0 (2026-02-16)

* feat: Add configurable note storage (text/JSON)

### 1.3.1 (2025-09-16)

* chore: bump dependencies

### 1.3.0 (2025-04-07)

* Adds support for filtering findings by region.
* Bump dependencies.

### 1.2.0 (2024-12-24)

* Updates default SecurityHub filter to fix issues with SecurityHub Integration findings support.
* Adjusted filtering logic to align with SecurityHub filtering: When both `match_on` options: `tags` and `resource_id_regexps` are specified, they are now combined using an **AND** condition instead of an **OR** condition.
* Introduce pagesize.

### 1.1.0 (2024-11-21)

* Adds support for SecurityHub Integration findings

### 1.0.4 (2024-10-14)

* Bump template python version to 3.12.
* Bugfixes.

### 1.0.3 (2024-10-04)

* Bump twine to latest version to fix upload on pipeline.

### 1.0.2 (2024-10-04)

* Fix development dependencies.

### 1.0.1 (2024-10-02)

* Bump template python version to 3.11.

### 1.0.0 (2024-07-26)

* Fix event handling.

### 0.1.2 (2024-06-19)

* Bump dependencies.

### 0.1.1 (2024-06-19)

* Fix s3 backend.

### 0.1.0 (2024-04-26)

* Initial release.
