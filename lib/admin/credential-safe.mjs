// Conservative credential-creation transport predicate. No routes use this yet.
// Private Compose HTTP is deliberately denied until the coordinated proxy tranche supplies
// actual private-path/exposed-peer evidence. Ordinary HTTP opt-in is never that evidence.
import { decideTransport, isLoopbackHost } from '../http/transport.mjs';

/** Recompute transport from the request and trusted-proxy predicate, never a body-supplied
 * safe flag. This is not CSRF/authorization: the pipeline must still enforce both first.
 * Only canonical HTTP(S) Origin values are admitted. Mixed forwarding-protocol headers are
 * denied until the proxy tranche's consistent-header parser is integrated (even if equal).
 */
export function credentialSafe({ req, access, trusted = null, configuredHosts = new Set() }) {
  if (!['interactive', 'basic'].includes(access?.kind)) return false;
  const headers = req?.headers;
  if (!headers || typeof headers.origin !== 'string' || typeof headers.host !== 'string')
    return false;
  let origin;
  try {
    origin = new URL(headers.origin);
  } catch {
    return false;
  }
  if (!['http:', 'https:'].includes(origin.protocol) || headers.origin !== origin.origin)
    return false;
  const host = headers.host.toLowerCase();
  if (origin.host !== host && !configuredHosts.has(origin.host)) return false;
  if (headers.forwarded !== undefined && headers['x-forwarded-proto'] !== undefined) return false;
  const transport = decideTransport({ peer: req.socket?.remoteAddress, headers, trusted });
  const interactive = access.kind === 'interactive';
  if (transport.kind === 'https')
    return origin.protocol === 'https:' && (!interactive || access.session?.transport === 'https');
  if (transport.kind === 'loopback')
    return (
      isLoopbackHost(origin.host) &&
      (!interactive || ['loopback', 'https'].includes(access.session?.transport))
    );
  return false;
}
