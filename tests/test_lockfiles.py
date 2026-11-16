"""Lockfile parser tests across every supported ecosystem."""

from __future__ import annotations

import json
from pathlib import Path

from pipelineguard.models import Component
from pipelineguard.scanners.deps import (
    collect_components,
    parse_cargo_lock,
    parse_go_sum,
    parse_package_lock,
    parse_pnpm_lock,
    parse_poetry_lock,
    parse_yarn_lock,
)
from tests.support import write_tree


def _by_name(project):
    return {component.name: component for component in project.components}


def test_package_lock_v3(tmp_path: Path):
    document = {
        "name": "demo",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "demo",
                "dependencies": {"lodash": "4.17.21"},
                "devDependencies": {"@scope/pkg": "1.2.3"},
            },
            "node_modules/lodash": {"version": "4.17.21", "license": "MIT"},
            "node_modules/@scope/pkg": {
                "version": "1.2.3",
                "license": {"type": "Apache-2.0"},
            },
            "node_modules/foo": {"version": "2.0.0"},
            "node_modules/foo/node_modules/bar": {"version": "1.0.0"},
        },
    }
    write_tree(tmp_path, {"package-lock.json": json.dumps(document)})
    project = parse_package_lock(tmp_path)
    components = _by_name(project)
    assert set(components) == {"lodash", "@scope/pkg", "foo", "bar"}
    assert components["lodash"].direct is True
    assert components["lodash"].license == "MIT"
    assert components["@scope/pkg"].license == "Apache-2.0"
    assert components["bar"].direct is False
    assert components["@scope/pkg"].purl == "pkg:npm/%40scope/pkg@1.2.3"


def test_package_lock_v1(tmp_path: Path):
    document = {
        "name": "demo",
        "lockfileVersion": 1,
        "dependencies": {
            "express": {
                "version": "4.19.2",
                "dependencies": {"cookie": {"version": "0.6.0"}},
            }
        },
    }
    write_tree(
        tmp_path,
        {
            "package-lock.json": json.dumps(document),
            "package.json": json.dumps({"dependencies": {"express": "^4.19.0"}}),
        },
    )
    project = parse_package_lock(tmp_path)
    components = _by_name(project)
    assert components["express"].direct is True
    assert components["cookie"].direct is False
    assert components["cookie"].version == "0.6.0"


def test_package_lock_invalid_json(tmp_path: Path):
    write_tree(tmp_path, {"package-lock.json": "{not json"})
    project = parse_package_lock(tmp_path)
    assert project.components == []


def test_yarn_lock_v1(tmp_path: Path):
    content = """
# yarn lockfile v1

lodash@^4.17.20, lodash@^4.17.21:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"

"@babel/core@^7.0.0":
  version "7.24.0"
  resolved "https://registry.yarnpkg.com/@babel/core/-/core-7.24.0.tgz"
"""
    write_tree(
        tmp_path,
        {
            "yarn.lock": content,
            "package.json": json.dumps(
                {"dependencies": {"lodash": "^4.17.21", "@babel/core": "^7.0.0"}}
            ),
        },
    )
    project = parse_yarn_lock(tmp_path)
    components = _by_name(project)
    assert set(components) == {"lodash", "@babel/core"}
    assert components["lodash"].version == "4.17.21"
    assert components["@babel/core"].direct is True


def test_yarn_lock_berry(tmp_path: Path):
    content = """
__metadata:
  version: 8
  cacheKey: 10c0

"lodash@npm:^4.17.21":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"
"""
    write_tree(tmp_path, {"yarn.lock": content})
    project = parse_yarn_lock(tmp_path)
    assert len(project.components) == 1
    assert project.components[0].name == "lodash"
    assert project.components[0].version == "4.17.21"


def test_pnpm_lock_v9(tmp_path: Path):
    content = """
lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      lodash:
        specifier: ^4.17.21
        version: 4.17.21

packages:
  lodash@4.17.21:
    resolution: {integrity: sha512-fake}
    license: MIT
  '@babel/core@7.24.0':
    resolution: {integrity: sha512-fake}
"""
    write_tree(tmp_path, {"pnpm-lock.yaml": content})
    project = parse_pnpm_lock(tmp_path)
    components = _by_name(project)
    assert components["lodash"].version == "4.17.21"
    assert components["lodash"].direct is True
    assert components["lodash"].license == "MIT"
    assert components["@babel/core"].direct is False


def test_pnpm_lock_v6(tmp_path: Path):
    content = """
lockfileVersion: 6.0

packages:
  /lodash@4.17.21:
    resolution: {integrity: sha512-fake}
  /@scope/pkg@1.2.3:
    resolution: {integrity: sha512-fake}
"""
    write_tree(
        tmp_path,
        {
            "pnpm-lock.yaml": content,
            "package.json": json.dumps({"dependencies": {"lodash": "4.17.21"}}),
        },
    )
    project = parse_pnpm_lock(tmp_path)
    components = _by_name(project)
    assert components["lodash"].version == "4.17.21"
    assert components["@scope/pkg"].version == "1.2.3"
    assert components["lodash"].direct is True


def test_go_sum_and_go_mod(tmp_path: Path):
    content = """
github.com/pkg/errors v0.9.1 h1:abc=
github.com/pkg/errors v0.9.1/go.mod h1:def=
golang.org/x/net v0.25.0 h1:ghi=
golang.org/x/net v0.25.0/go.mod h1:jkl=
"""
    write_tree(
        tmp_path,
        {
            "go.sum": content,
            "go.mod": "module demo\n\ngo 1.22\n\nrequire github.com/pkg/errors v0.9.1\n",
        },
    )
    project = parse_go_sum(tmp_path)
    assert len(project.components) == 2
    components = _by_name(project)
    assert components["github.com/pkg/errors"].direct is True
    assert components["golang.org/x/net"].direct is False
    assert components["golang.org/x/net"].purl == "pkg:golang/golang.org/x/net@v0.25.0"


def test_cargo_lock(tmp_path: Path):
    content = """
[[package]]
name = "serde"
version = "1.0.203"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc"

[[package]]
name = "demo"
version = "0.1.0"

[[package]]
name = "regex"
version = "1.10.4"
source = "registry+https://github.com/rust-lang/crates.io-index"
"""
    write_tree(
        tmp_path,
        {
            "Cargo.lock": content,
            "Cargo.toml": '[package]\nname = "demo"\nversion = "0.1.0"\n\n[dependencies]\nserde = "1.0"\n',
        },
    )
    project = parse_cargo_lock(tmp_path)
    components = _by_name(project)
    assert components["serde"].direct is True
    assert components["regex"].direct is False
    assert components["demo"].direct is True
    assert components["serde"].purl == "pkg:cargo/serde@1.0.203"


def test_poetry_lock(tmp_path: Path):
    content = """
[[package]]
name = "jinja2"
version = "3.1.4"
description = "A template engine"
optional = false
python-versions = ">=3.7"

[[package]]
name = "markupsafe"
version = "2.1.5"
optional = false
python-versions = ">=3.7"
"""
    write_tree(tmp_path, {"poetry.lock": content})
    project = parse_poetry_lock(tmp_path)
    components = _by_name(project)
    assert set(components) == {"jinja2", "markupsafe"}
    assert components["jinja2"].direct is False
    assert components["jinja2"].purl == "pkg:pypi/jinja2@3.1.4"


def test_collect_components_multi_ecosystem(tmp_path: Path):
    write_tree(
        tmp_path,
        {
            "requirements.txt": "jinja2==3.1.4\n",
            "package-lock.json": json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {
                        "": {"dependencies": {"lodash": "4.17.21"}},
                        "node_modules/lodash": {"version": "4.17.21", "license": "MIT"},
                    },
                }
            ),
            "go.sum": "github.com/pkg/errors v0.9.1 h1:abc=\n",
        },
    )
    project = collect_components(tmp_path)
    ecosystems = {component.ecosystem for component in project.components}
    assert ecosystems == {"pypi", "npm", "golang"}
    assert len(project.components) == 3


def test_component_ordering_is_deterministic():
    components = [
        Component(ecosystem="npm", name="zeta", version="1.0.0"),
        Component(ecosystem="pypi", name="Alpha", version="2.0.0"),
        Component(ecosystem="cargo", name="serde", version="1.0.0"),
    ]
    from pipelineguard.scanners.deps import dedupe_components

    first = [component.purl for component in dedupe_components(components)]
    second = [component.purl for component in dedupe_components(reversed(components))]
    assert first == second
    assert first == [
        "pkg:cargo/serde@1.0.0",
        "pkg:npm/zeta@1.0.0",
        "pkg:pypi/alpha@2.0.0",
    ]


def test_purl_shapes():
    cases = {
        ("pypi", "Jinja2", "3.1.4"): "pkg:pypi/jinja2@3.1.4",
        ("npm", "@scope/pkg", "1.2.3"): "pkg:npm/%40scope/pkg@1.2.3",
        ("golang", "github.com/pkg/errors", "v0.9.1"): "pkg:golang/github.com/pkg/errors@v0.9.1",
        ("cargo", "serde", "1.0.203"): "pkg:cargo/serde@1.0.203",
    }
    for (ecosystem, name, version), expected in cases.items():
        assert Component(ecosystem=ecosystem, name=name, version=version).purl == expected
