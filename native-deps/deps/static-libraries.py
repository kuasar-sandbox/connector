#!/usr/bin/env python3
"""Collect distribution notices for system code actually linked into VPP."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def linked_files(link_map, build_root):
    """Both GNU ld and LLD identify archive members as path.a(member.o)."""
    text = link_map.read_text()
    names = set(re.findall(r'(?<!\S)([^\s():]+\.a)(?=\(|\s|$)', text))
    names.update(re.findall(r'(?<!\S)(/[^\s():]*/(?:[SM]?crt[^/\s():]*|crtbegin[^/\s():]*|crtend[^/\s():]*)\.o)(?=\s|:|$)', text))
    files = set()
    for name in names:
        path = Path(name)
        path = (path if path.is_absolute() else build_root / path).resolve()
        if path.is_relative_to(build_root):
            continue
        if not path.is_file():
            raise ValueError('linked system input is missing: ' + str(path))
        files.add(path)
    if not any(path.suffix == '.a' for path in files):
        raise ValueError('link map contains no system static archives')
    return sorted(files)


def package_for(path):
    if shutil.which('dpkg-query'):
        owner = command('dpkg-query', '--search', str(path))
        candidates = {line.rsplit(': ', 1)[0] for line in owner.splitlines()
                      if line.endswith(': ' + str(path))}
        if len(candidates) != 1:
            raise ValueError('cannot identify one package for ' + str(path))
        name = candidates.pop()
        metadata = command('dpkg-query', '--show',
                           '--showformat=${binary:Package}\t${Version}\t${source:Package}\t${source:Version}', name)
        binary, version, source, source_version = metadata.split('\t')
        notice = Path('/usr/share/doc') / binary.split(':')[0] / 'copyright'
        notices = [notice.resolve()]
        record = dict(name=binary, version=version, source=source,
                      source_version=source_version)
    elif shutil.which('rpm'):
        metadata = command('rpm', '--query', '--file', str(path),
                           '--queryformat', '%{NAME}\t%{VERSION}-%{RELEASE}\t%{SOURCERPM}')
        binary, version, source = metadata.split('\t')
        notices = [Path(name).resolve() for name in
                   command('rpm', '--query', '--licensefiles', binary).splitlines() if name]
        record = dict(name=binary, version=version, source=source)
    else:
        raise ValueError('static release notices require a dpkg or RPM managed toolchain')
    if not notices or any(not p.is_file() or p.stat().st_size == 0 for p in notices):
        raise ValueError('missing distribution license material for ' + record['name'])
    return record, notices


def collect(link_map, build_root, output, record_path):
    files = linked_files(link_map, build_root)
    packages = {}
    observations = []
    for path in files:
        package, notices = package_for(path)
        observations.append(dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                                 package=package))
        packages[package['name']] = (package, notices)
    output.mkdir(parents=True, exist_ok=False)
    for name, (package, notices) in sorted(packages.items()):
        if not re.fullmatch(r'[A-Za-z0-9_.+:-]+', name):
            raise ValueError('unsafe system package name: ' + name)
        destination = output / name
        destination.mkdir()
        for notice in notices:
            content = notice.read_bytes()
            target = destination / notice.name
            if target.exists() and target.read_bytes() != content:
                raise ValueError('conflicting license files for ' + name)
            target.write_bytes(content)
            # Debian-family copyright files refer to these full license texts.
            for reference in re.findall(rb'/usr/share/common-licenses/([A-Za-z0-9_.+-]+)', content):
                basename = reference.decode().rstrip('.')
                full = Path('/usr/share/common-licenses') / basename
                if not full.is_file():
                    raise ValueError('referenced system license is missing: ' + str(full))
                (destination / basename).write_bytes(full.read_bytes())
    for path in output.rglob('*'):
        path.chmod(0o755 if path.is_dir() else 0o644)
    output.chmod(0o755)
    # Build observations remain beside the object files, like other native
    # dependency build reports; only license texts enter the release package.
    record_path.write_text(json.dumps(dict(schema=1, libraries=observations), indent=2) + '\n')
    record_path.chmod(0o644)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--link-map', required=True, type=Path)
    parser.add_argument('--build-root', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--record', required=True, type=Path)
    args = parser.parse_args()
    collect(args.link_map.resolve(), args.build_root.resolve(), args.output, args.record)


if __name__ == '__main__':
    main()
