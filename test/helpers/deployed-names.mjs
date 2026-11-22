// .env.example keeps the names from before the rename to Uptime Goblin until the rename's last
// step changes it; the other deployment files (compose*.yaml, the Dockerfile, deploy/) use the new
// names since the installer and container step. Uptime Goblin accepts the old names
// (lib/legacy-names.mjs), so an .env.example line that still says ORBIT_PASSWORD configures the
// same thing. The documentation tests compare it with the documents and the code by the current
// names: currentNames() gives its text with the old identifiers written as the new ones (never the
// product's name in prose). Once it uses the new names, this helper can go.

const rules = [
  [/\bORBIT_(?!SECURITY_|SONAR_|SIGNING_KEY)/g, 'GOBLIN_'],
  [/orbit-admin/g, 'goblin-admin'],
  [
    /\bX-Orbit-(Request|Client|Activity|Build|Version|Export-Rows|Export-More|Signature|Delivery)\b/g,
    'X-Goblin-$1',
  ],
  [/\b(__Host-)?orbit_session\b/g, '$1goblin_session'],
  [/\/etc\/orbit\.env/g, '/etc/uptime-goblin.env'],
  [/\/etc\/orbit\//g, '/etc/uptime-goblin/'],
  [/\/opt\/orbit\b/g, '/opt/uptime-goblin'],
  [/\/var\/lib\/orbit\b/g, '/var/lib/uptime-goblin'],
  [/\borbit\.service\b/g, 'uptime-goblin.service'],
  [/\borbit\.lock\b/g, 'goblin.lock'],
  [/(systemctl (?:[a-z-]+ )*?(?:--[a-z-]+ )*)orbit\b(?![-\w]|\.\w)/g, '$1uptime-goblin'],
  [/journalctl -u orbit\b/g, 'journalctl -u uptime-goblin'],
  [/sudo -u orbit\b/g, 'sudo -u uptime-goblin'],
  [/\broot:orbit\b/g, 'root:uptime-goblin'],
  [
    /((?:--no-deps|-T|exec|stop|logs|restart|start|up -d|rm|kill|--no-log-prefix)\s+)orbit\b(?![-\w]|\.\w)/g,
    '$1uptime-goblin',
  ],
  [/\b(the|The) orbit (account|user|group)\b/g, '$1 uptime-goblin $2'],
];

/** `text` with the identifiers from before the rename written as the current ones. */
export function currentNames(text) {
  return rules.reduce((value, [pattern, replacement]) => value.replace(pattern, replacement), text);
}

/** Whether `file` (relative to the repository) is the deployment file still to be renamed. */
export function isDeploymentFile(file) {
  return file === '.env.example';
}
