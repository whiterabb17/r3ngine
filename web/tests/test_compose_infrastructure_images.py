"""Third-party images in the compose files are pinned, and the Temporal pieces agree.

A floating tag (redis:alpine) moved Redis across a major version under existing
data; Redis cannot load an RDB written by a newer release. The Temporal server,
its schema job and scripts/temporal_upgrade.sh must name the same release, or
the schema job refuses to start the server.
"""
import re
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DOCKER_DIR = REPO_ROOT / 'docker'
UPGRADE_SCRIPT = REPO_ROOT / 'scripts' / 'temporal_upgrade.sh'
COMPOSE_FILES = ('docker-compose.yml', 'docker-compose.dev.yml')


def _services(name: str) -> dict:
    return yaml.safe_load((DOCKER_DIR / name).read_text(encoding='utf-8'))['services']


def _tag(image: str) -> str:
    return image.rsplit(':', 1)[1] if ':' in image.rsplit('/', 1)[-1] else ''


def _last_upgrade_hop() -> str:
    text = UPGRADE_SCRIPT.read_text(encoding='utf-8')
    hops = re.search(r'HOPS="\n(.*?)\n"', text, re.S)
    assert hops, 'HOPS table not found in scripts/temporal_upgrade.sh'
    return hops.group(1).strip().splitlines()[-1].split()[0]


class ComposeInfrastructureImagesTest(unittest.TestCase):

    def test_third_party_images_carry_a_version(self):
        offenders = []
        for name in COMPOSE_FILES:
            for service, spec in _services(name).items():
                image = spec.get('image', '')
                # Built locally (tor, ollama, mcp) or the app image itself.
                if not image or 'build' in spec or image.startswith('${'):
                    continue
                tag = _tag(image)
                if not re.search(r'\d', tag) or 'latest' in tag:
                    offenders.append(f'{name}:{service}: {image}')
        self.assertEqual(offenders, [], 'pin these images to a version:\n' + '\n'.join(offenders))

    def test_temporal_server_schema_job_and_upgrade_script_agree(self):
        target = _last_upgrade_hop()
        for name in COMPOSE_FILES:
            services = _services(name)
            with self.subTest(compose=name):
                self.assertEqual(services['temporal']['image'], f'temporalio/server:{target}')
                self.assertEqual(services['temporal-schema']['image'], f'temporalio/admin-tools:{target}')
                self.assertEqual(services['temporal-create-namespace']['image'], f'temporalio/admin-tools:{target}')

    def test_temporal_waits_for_its_schema_and_workers_start_the_namespace_job(self):
        for name in COMPOSE_FILES:
            services = _services(name)
            with self.subTest(compose=name):
                self.assertEqual(
                    services['temporal']['depends_on']['temporal-schema']['condition'],
                    'service_completed_successfully',
                )
                # `make up` names its services; the job only runs because a named one depends on it.
                self.assertEqual(
                    services['temporal-python-orchestrator']['depends_on']['temporal-create-namespace']['condition'],
                    'service_completed_successfully',
                )
                self.assertIn('DB=postgres12', services['temporal']['environment'])

    def test_temporal_job_scripts_and_dynamic_config_exist(self):
        for path in ('temporal/setup-schema.sh', 'temporal/create-namespace.sh', 'temporal/dynamicconfig/docker.yaml'):
            self.assertTrue((DOCKER_DIR / path).is_file(), f'docker/{path} is mounted by the temporal services')


if __name__ == '__main__':
    unittest.main()
