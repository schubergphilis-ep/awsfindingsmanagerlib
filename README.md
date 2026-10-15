# awsfindingsmanagerlib

Rule-based Python library for managing and suppressing findings in AWS Security Hub and its integrated services

Full documentation, including rule syntax and code examples, is available
[here](https://schubergphilis-ep.github.io/awsfindingsmanagerlib/).

## Features

- Rules map directly onto the `get_findings`/`batch_update_findings` boto3 API, so anything the
  Security Hub API supports as a filter or update is available without extra abstraction.
- A `Manager` lets you set shared defaults (filters, updates, note handling) once and have
  individual rules override only what differs.
- Regex matching on string fields (`ExtraFeatures.RegexStringFilters`), not natively supported by
  the API, is layered on top.
- JSON-formatted suppression notes (`ExtraFeatures.NoteTextConfig`) merge into existing
  JSON-formatted note metadata, e.g. to coexist with a ticketing system's own note fields.
- Ready-made AWS Lambda handlers (`awsfindingsmanagerlib[lambda]`) for running suppression on a schedule, or
  as an event-driven pipeline reacting to new findings and to rules-file changes.

## Installation

```bash
uv add awsfindingsmanagerlib
# or, with the AWS Lambda handlers:
uv add 'awsfindingsmanagerlib[lambda]'
```

```bash
pip install awsfindingsmanagerlib
# or
pip install 'awsfindingsmanagerlib[lambda]'
```

## Quick start

```python
from pathlib import Path

import boto3
import yaml

from awsfindingsmanagerlib import Rule


with Path("rules.yaml").open() as file:
    rules = yaml.safe_load(file)["Rules"]

client = boto3.client("securityhub")

rule = Rule(**rules[0], client=client)
rule.get_and_update()
```

See the [documentation](https://schubergphilis-ep.github.io/awsfindingsmanagerlib/) for the full rule syntax,
the `Manager` API for managing many rules at once, and how to run awsfindingsmanagerlib as an AWS Lambda.

## Upgrading

Coming from 1.x? Version 2.0 is a rewrite with a different rules schema and Python API.
See [UPGRADING.md](UPGRADING.md).

## Developing further

> Development flow as [Paleofuturistic Python](https://github.com/schubergphilis/paleofuturistic_python)

Prerequisite: [uv](https://docs.astral.sh/uv/)

### Setup

- Fork and clone this repository.
- Download additional dependencies: `uv sync --all-extras --dev`
- Optional: validate the setup with `uv run python -m unittest`

### Workflow

- Download dependencies (if you need any): `uv add some_lib_you_need`
- Develop (optional, tinker: `uvx --with-editable . ptpython`)
- QA:
    - Format: `uv run ruff format`
    - Lint: `uv run ruff check`
    - Type check: `uv run mypy`
    - Test: `uv run python -m unittest`
- Build (to validate it works): `uv build`
- Review documentation updates: `uv run mkdocs serve`
- Make a pull request.
