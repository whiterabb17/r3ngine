"""No compose file may mount the Docker socket into a container.

Access to /var/run/docker.sock is root on the host; the application no longer
needs it (plugin restarts exit the process, tool probes run on the
orchestrator, Tor and Ollama are compose profile services).
"""
import unittest
from pathlib import Path

DOCKER_DIR = Path(__file__).resolve().parent.parent.parent / 'docker'


class ComposeNoDockerSocketTest(unittest.TestCase):

    def test_no_compose_file_mounts_the_docker_socket(self):
        files = sorted(DOCKER_DIR.glob('docker-compose*.yml'))
        self.assertGreaterEqual(len(files), 3, f'expected the compose files under {DOCKER_DIR}')
        offenders = []
        for path in files:
            for lineno, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
                stripped = line.strip()
                if 'docker.sock' in stripped and not stripped.startswith('#'):
                    offenders.append(f'{path.name}:{lineno}: {stripped}')
        self.assertEqual(offenders, [], 'docker.sock must not be mounted:\n' + '\n'.join(offenders))

    def test_tor_and_ollama_are_profile_services(self):
        import yaml

        main = yaml.safe_load((DOCKER_DIR / 'docker-compose.yml').read_text(encoding='utf-8'))
        services = main['services']
        self.assertEqual(services['tor'].get('profiles'), ['tor'])
        self.assertEqual(services['ollama'].get('profiles'), ['ollama'])
        for name in ('web', 'temporal-python-orchestrator', 'tor'):
            self.assertIn(
                'TOR_CONTROL_PASSWORD=${TOR_CONTROL_PASSWORD:-}', services[name]['environment'],
                f'{name} must receive the shared Tor control password',
            )
