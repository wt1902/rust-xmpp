#!/usr/bin/env python3
"""Validate Gitea publication inputs and emit literal, shell-safe image tags."""
import os
import re
import tomllib
from pathlib import Path


def image_tags(env, version):
    registry = env.get('GITEA_REGISTRY', '')
    image = env.get('GITEA_IMAGE', '')
    if not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[0-9]{1,5})?', registry):
        raise ValueError('GITEA_REGISTRY must be a lowercase hostname[:port], without scheme or path')
    if not re.fullmatch(r'[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)+', image):
        raise ValueError('GITEA_IMAGE must be lowercase owner/image, without registry or tag')
    if not env.get('REGISTRY_USER') or not env.get('REGISTRY_TOKEN'):
        raise ValueError('Set GITEA_REGISTRY_USERNAME and GITEA_REGISTRY_TOKEN secrets')
    sha = env['GITHUB_SHA']
    if not re.fullmatch(r'[0-9a-f]{40}', sha):
        raise ValueError('Invalid commit SHA')
    base = f'{registry}/{image}'
    tags = [f'{base}:sha-{sha}']
    ref = env['GITHUB_REF']
    if ref.startswith('refs/tags/'):
        release = ref.removeprefix('refs/tags/')
        if release != f'v{version}' or not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?', release):
            raise ValueError('Release tag must be v<Cargo.toml package.version> (no build metadata)')
        tags.append(f'{base}:{release.lower()}')
    elif ref == 'refs/heads/' + env['DEFAULT_BRANCH']:
        tags.append(f'{base}:latest')
    else:
        raise ValueError('Only default branch or version tags may publish')
    return tags


def main():
    version = tomllib.loads(Path('Cargo.toml').read_text())['package']['version']
    tags = image_tags(os.environ, version)
    with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as out:
        out.write('tags<<IMAGE_TAGS\n' + '\n'.join(tags) + '\nIMAGE_TAGS\n')


if __name__ == '__main__':
    main()
