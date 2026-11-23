#!/usr/bin/env bash
# Install or upgrade Uptime Goblin inside an existing Debian/Ubuntu LXC. No host or firewall changes.
#
# Usage: sudo bash deploy/install.sh [options]
#   --listen <address>         HOST for a new /etc/uptime-goblin.env (default 127.0.0.1)
#   --allowed-hosts <names>    GOBLIN_ALLOWED_HOSTS for a new /etc/uptime-goblin.env
#   --trust-proxy <proxies>    GOBLIN_TRUST_PROXY: loopback, addresses/CIDR ranges, or off
#   --allow-loopback           GOBLIN_ALLOW_LOOPBACK=1: sources on this host's loopback
#   --allow-insecure-http      GOBLIN_INSECURE_HTTP_SESSIONS=1 where neither /etc/uptime-goblin.env nor
#                              anything else systemd would give Uptime Goblin says yes or no (or only
#                              an earlier 1.5 pre-release installer set it, which it then
#                              records as your choice): sign-in over plain HTTP, passwords in
#                              clear on the network
#   --proxy-proto-checked      skip the 1.4.x proxy preflight (you checked X-Forwarded-Proto)
#   --verify-timeout <seconds> how long to wait for the new release to serve (default 120)
#   --allow-downgrade          install a release older than the one installed (refused without it,
#                              exit status 2, before anything changes: restore data first)
#   --restore-orbit-layout     go back to the Orbit release this installer migrated from, after
#                              an upgrade that worked: see "Going back to Orbit" below (takes no
#                              other option but --verify-timeout)
# An install that listens on the network (HOST not a loopback address) without a trusted proxy
# stops before anything changes unless systemd would give Uptime Goblin a GOBLIN_INSECURE_HTTP_SESSIONS
# that says yes or no or --allow-insecure-http is given: the installer never allows plain-HTTP
# sign-in by itself. Any install whose /etc/uptime-goblin.env holds the GOBLIN_INSECURE_HTTP_SESSIONS=1
# that earlier 1.5 pre-release installers added by themselves stops too, on loopback and behind a
# trusted proxy as well, until that line is decided or --allow-insecure-http is given. One whose
# data directory has no auth.json and to which systemd would give no GOBLIN_PASSWORD, an empty one
# or one that Uptime Goblin refuses (under 12 characters, for one) stops too: Uptime Goblin would not start, and
# so does one whose auth.json Uptime Goblin's start would refuse (read with Uptime Goblin's own reader, as root: a
# symbolic link, not a regular file, over 8192 bytes or not a valid password record), whatever
# GOBLIN_PASSWORD is, and one to which systemd would give another setting this release refuses to
# start with. One whose auth.json the uptime-goblin account, which Uptime Goblin runs as, cannot read stops later,
# once the data directory is that account's, but before the service stops.
# The files installed are exactly those in deploy/manifest.txt. After (re)starting the service
# the installer proves that the new version is the one serving; otherwise it prints the service
# log, restores the previous code from /opt/uptime-goblin.previous and exits non-zero (an earlier 1.5
# pre-release build that signs webhooks with an HMAC secret it neither restores nor starts,
# whatever GOBLIN_WEBHOOK_URL is: see the end).
#
# Renamed from Orbit. On a host that still has the Orbit layout (orbit.service, /opt/orbit,
# /var/lib/orbit, /etc/orbit.env, /etc/orbit/secret.key, the orbit account), every check above
# reads the files where they are, and the upgrade then moves them to the Uptime Goblin layout in
# one guarded, logged step, after those checks and in place of the service's stop: it stops
# orbit.service; renames /var/lib/orbit to /var/lib/uptime-goblin; writes /etc/uptime-goblin.env
# from /etc/orbit.env (each ORBIT_ name as its GOBLIN_ one, values as they were, a path in
# /etc/orbit or /var/lib/orbit as its new path; mode 0600) and keeps the old file as
# /etc/orbit.env.migrated; renames /etc/orbit to /etc/uptime-goblin (modes kept); renames the
# account and its group (usermod -l, groupmod -n: the files keep their owner); renames
# orbit.service.d to uptime-goblin.service.d, disables orbit.service and keeps its unit file as
# orbit.service.migrated; and renames /opt/orbit to /opt/uptime-goblin, which the normal upgrade
# then keeps as /opt/uptime-goblin.previous. Every move is a rename on one file system: a move
# that would cross file systems (or a mount point, or a symbolic link) is refused before anything
# changes. A failed upgrade restores the Orbit layout exactly (the steps undone in reverse, the
# account and unit renamed back, orbit.service enabled and started again as it was), then checks
# that the previous release serves; a key the key step wrote to /etc/orbit before the move (a
# host that had none) is moved back and kept, with its line in /etc/orbit.env, as what the failed
# start sealed needs it. A record of the migration under way
# (/var/lib/uptime-goblin.migrating) makes it re-runnable: a run that was cut short (killed, or
# the power lost) is undone by the next run before its checks, which then migrate again.
#
# Going back to Orbit. --restore-orbit-layout, run from the staging directory of the release
# installed now, undoes such a migration after the upgrade worked: it puts the Orbit layout back
# with the Orbit release the upgrade kept in /opt/uptime-goblin.previous (1.4.x reads only its
# ORBIT_ settings and the Orbit paths), from the settings file and unit kept as
# /etc/orbit.env.migrated and orbit.service.migrated, starts orbit.service and checks that it
# serves. It refuses, changing nothing, unless both of those are there, the copy in
# /opt/uptime-goblin.previous is a release before 1.5, no part of the Orbit layout is in the way,
# and every move is a rename on one file system. Each step is the migration's rollback, with the
# same record, so a run cut short is finished by the next run. The settings Uptime Goblin ran with
# are kept as /etc/uptime-goblin.env.kept, and this release in /opt/uptime-goblin.failed; the
# data stays as Uptime Goblin left it, which 1.4.x reads (docs/installation.md, Rolling back 1.5 to
# 1.4.3). The next upgrade migrates again.
set -euo pipefail
umask 077
# systemd starts Uptime Goblin without this installer's environment. The checks that Uptime Goblin serves, after
# the start and after a rollback, run node --env-file=/etc/uptime-goblin.env, which never replaces a
# variable already set: a HOST or PORT this installer was started with (as root without sudo,
# with sudo -E or env_keep, or from a wrapper that exports them) made them probe another address
# or port than Uptime Goblin's, so a working upgrade was rolled back and the restored release reported
# "could not be verified" (one before 1.4.3: its legacy health check "did not pass", or
# "answered" without a verified process identity when something there answered it). Removed
# before anything runs, so every node started below reads HOST and PORT from /etc/uptime-goblin.env
# alone, which is what the HOST/PORT preflights below compare with what systemd gives Uptime Goblin.
unset HOST PORT
goblin_host=127.0.0.1
goblin_hosts=localhost:4317
goblin_trust_proxy=
goblin_allow_loopback=
goblin_proxy_proto_checked=
goblin_allow_insecure_http=
goblin_verify_timeout=120
goblin_allow_downgrade=
goblin_restore=
goblin_listen_given=
goblin_hosts_given=
goblin_fail() {
  printf '%s\n' "$1" >&2
  exit "${2:-1}"
}
# Every usage problem exits 2 before anything is read: an option given twice (the last one won
# silently), a missing or empty value (${2:?} exited 1, as a failed install does), an unknown one.
goblin_seen=' '
goblin_value() {
  [[ -n $2 && $2 != --* ]] || goblin_fail "$1 needs a value: $3." 2
}
while (($#)); do
  case "$1" in
    --listen | --allowed-hosts | --trust-proxy | --allow-loopback | --allow-insecure-http | --proxy-proto-checked | --verify-timeout | --allow-downgrade | --restore-orbit-layout)
      [[ $goblin_seen != *" $1 "* ]] || goblin_fail "$1 is given more than once." 2
      goblin_seen+="$1 " ;;
  esac
  case "$1" in
    --listen) goblin_host=${2-}; goblin_value "$1" "$goblin_host" 'the address Uptime Goblin listens on, such as 0.0.0.0'; goblin_listen_given=1; shift 2 ;;
    --allowed-hosts) goblin_hosts=${2-}; goblin_value "$1" "$goblin_hosts" 'host names, comma-separated, such as goblin.example'; goblin_hosts_given=1; shift 2 ;;
    --trust-proxy) goblin_trust_proxy=${2-}; goblin_value "$1" "$goblin_trust_proxy" 'loopback for a proxy on this host, its address/CIDR, or off'; shift 2 ;;
    --allow-loopback) goblin_allow_loopback=1; shift ;;
    --allow-insecure-http) goblin_allow_insecure_http=1; shift ;;
    --proxy-proto-checked) goblin_proxy_proto_checked=1; shift ;;
    --allow-downgrade) goblin_allow_downgrade=1; shift ;;
    --restore-orbit-layout) goblin_restore=1; shift ;;
    --verify-timeout) goblin_verify_timeout=${2-}; goblin_value "$1" "$goblin_verify_timeout" 'seconds, 1 to 1800'; shift 2 ;;
    *) goblin_fail "Unknown option: $(printf '%q' "$1")
Options: --listen <address>, --allowed-hosts <names>, --trust-proxy <proxies>, --allow-loopback, --allow-insecure-http, --proxy-proto-checked, --verify-timeout <seconds>, --allow-downgrade, --restore-orbit-layout (see the start of deploy/install.sh)." 2 ;;
  esac
done
# Going back to Orbit installs nothing, so no install option applies to it.
if [[ -n $goblin_restore && $goblin_seen != ' --restore-orbit-layout ' && $goblin_seen != ' --restore-orbit-layout --verify-timeout ' && $goblin_seen != ' --verify-timeout --restore-orbit-layout ' ]]; then
  goblin_fail '--restore-orbit-layout takes no other option but --verify-timeout: it installs nothing.' 2
fi
# Tests install into a scratch directory with fake systemctl/journalctl on PATH, and say so with
# GOBLIN_INSTALLER_TEST=1 too. Real installs never set either: sudo resets the environment, and
# every path below then starts at /. One that reached root anyway (sudo -E, env_keep, a root
# shell profile) would put the files under it while systemctl, runuser and journalctl act on
# this host, so it is refused unless the test guard is set as well. The names from before the
# rename (ORBIT_INSTALL_ROOT, ORBIT_INSTALLER_TEST) are read as these, as Uptime Goblin reads
# every ORBIT_ setting: refused the same way, and both names set to different values is refused.
for goblin_name in INSTALL_ROOT INSTALLER_TEST; do
  goblin_new=GOBLIN_$goblin_name goblin_old=ORBIT_$goblin_name
  if [[ -n ${!goblin_old+set} ]]; then
    [[ -z ${!goblin_new+set} || ${!goblin_new} == "${!goblin_old}" ]] || goblin_fail "$goblin_new and $goblin_old are both set, to different values. Run the installer without them." 2
    printf -v "$goblin_new" '%s' "${!goblin_old}"
  fi
done
goblin_root=${GOBLIN_INSTALL_ROOT:-}
[[ -z $goblin_root || ${GOBLIN_INSTALLER_TEST:-} == 1 ]] || goblin_fail 'GOBLIN_INSTALL_ROOT is set, but it is only for the installer tests. Run the installer without it (sudo env -u GOBLIN_INSTALL_ROOT bash deploy/install.sh …).' 2
[[ -z $goblin_root || ($goblin_root == /* && -d $goblin_root) ]] || goblin_fail 'GOBLIN_INSTALL_ROOT must be an existing absolute directory.' 2
goblin_app=$goblin_root/opt/uptime-goblin
goblin_previous=$goblin_root/opt/uptime-goblin.previous
goblin_reinstall=$goblin_root/opt/uptime-goblin.reinstall
goblin_stage=$goblin_root/opt/uptime-goblin.new
goblin_failed=$goblin_root/opt/uptime-goblin.failed
goblin_data=$goblin_root/var/lib/uptime-goblin
goblin_env=$goblin_root/etc/uptime-goblin.env
goblin_unit=$goblin_root/etc/systemd/system/uptime-goblin.service
goblin_key_home=$goblin_root/etc/uptime-goblin
# The Orbit layout that a host upgraded from a release before 1.5 still has (see the start).
legacy_app=$goblin_root/opt/orbit
legacy_data=$goblin_root/var/lib/orbit
legacy_env=$goblin_root/etc/orbit.env
legacy_key_home=$goblin_root/etc/orbit
legacy_unit=$goblin_root/etc/systemd/system/orbit.service
goblin_journal=$goblin_root/var/lib/uptime-goblin.migrating
[[ $(id -u) == 0 ]] || goblin_fail 'Run this installer with sudo inside the LXC.'
[[ $(uname -s) == Linux && -d $goblin_root/run/systemd/system ]] || goblin_fail 'A running Linux systemd environment is required.'
# Brackets for an IPv6 host value such as [::1]:4317 (Uptime Goblin's own rule is applied below).
goblin_hosts_pattern='^[][A-Za-z0-9.,:_-]+$'
[[ $goblin_host =~ ^[A-Za-z0-9.:_-]+$ && $goblin_hosts =~ $goblin_hosts_pattern ]] || goblin_fail 'Invalid listen address or hostname list.' 2
[[ -z $goblin_trust_proxy || $goblin_trust_proxy =~ ^[-A-Za-z0-9.:/,]+$ ]] || goblin_fail 'Invalid --trust-proxy value.' 2
# Decimal, also with leading zeros: bash reads 0010 as octal 8 (and 08 as an error).
[[ $goblin_verify_timeout =~ ^[0-9]{1,4}$ ]] && goblin_verify_timeout=$((10#$goblin_verify_timeout)) &&
  ((goblin_verify_timeout >= 1 && goblin_verify_timeout <= 1800)) || goblin_fail '--verify-timeout takes 1 to 1800 seconds.' 2
# The unit keeps the path the shell finds (for example /usr/bin/node), not the versioned file it
# points to today: a Node upgrade replaces that file, and a frozen path would stop the service.
goblin_node=$(command -v node || true)
[[ -n $goblin_node ]] || goblin_fail 'Install Node.js 24 or newer first, then run this again.'
[[ $goblin_node =~ ^/[A-Za-z0-9._+/-]+$ && -x $goblin_node ]] || goblin_fail "Node.js was found as '$goblin_node'; install it at a plain absolute path such as /usr/bin/node."
goblin_node_real=$(readlink -f "$goblin_node" || printf '%s' "$goblin_node")
for goblin_path in "$goblin_node" "$goblin_node_real"; do
  case "$goblin_path" in /root/*|/home/*|/run/user/*) goblin_fail 'Install Node in a system directory; the Uptime Goblin service cannot access home directories.' ;; esac
done
"$goblin_node" -e 'if(Number(process.versions.node.split(".")[0])<24)process.exit(1);require("node:sqlite")' || goblin_fail "Node.js 24+ with SQLite is required ($goblin_node is $("$goblin_node" --version 2>/dev/null || printf 'not runnable'))."
goblin_npm=$(command -v npm || true)
[[ -n $goblin_npm ]] || goblin_fail 'Install npm with Node.js before running this installer.'
goblin_source=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
for goblin_path in "$goblin_app" "$goblin_previous" "$goblin_reinstall" "$goblin_stage" "$goblin_failed" "$legacy_app" "$legacy_app.previous" "$legacy_app.failed"; do
  [[ -d $goblin_path ]] && goblin_path=$(cd -- "$goblin_path" && pwd -P)
  [[ $goblin_source != "$goblin_path" && $goblin_source != "$goblin_path"/* ]] || goblin_fail 'Run the installer from a staging directory such as /usr/local/src/uptime-goblin, not from the installed copy.'
done
# Read and validate the manifest before anything on this host changes.
goblin_manifest=$goblin_source/deploy/manifest.txt
[[ -f $goblin_manifest ]] || goblin_fail 'Missing application file: deploy/manifest.txt'
goblin_files=()
while IFS= read -r goblin_line || [[ -n $goblin_line ]]; do
  [[ -z $goblin_line || $goblin_line == '#'* ]] && continue
  [[ $goblin_line =~ ^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$ && /$goblin_line/ != */./* && /$goblin_line/ != */../* ]] || goblin_fail "Invalid manifest entry: $goblin_line"
  [[ -f $goblin_source/$goblin_line && ! -L $goblin_source/$goblin_line ]] || goblin_fail "Missing application file: $goblin_line"
  goblin_files+=("$goblin_line")
done <"$goblin_manifest"
for goblin_required in server.mjs package.json package-lock.json lib/healthcheck.mjs deploy/manifest.txt; do
  goblin_found=
  for goblin_file in "${goblin_files[@]}"; do [[ $goblin_file == "$goblin_required" ]] && goblin_found=1; done
  [[ -n $goblin_found ]] || goblin_fail "deploy/manifest.txt must list $goblin_required."
done
[[ -f $goblin_source/deploy/uptime-goblin.service && $(grep -c '^ExecStart=' "$goblin_source/deploy/uptime-goblin.service") == 1 ]] || goblin_fail 'Missing or invalid deploy/uptime-goblin.service.'
# A release archive carries SHA256SUMS: every installed file must match it. (Verify the
# signature on SHA256SUMS first; see docs/installation.md.) A source checkout has none.
if [[ -f $goblin_source/SHA256SUMS ]]; then
  "$goblin_node" - "$goblin_source" "${goblin_files[@]}" deploy/uptime-goblin.service deploy/install.sh <<'NODE' || goblin_fail 'The release files do not match SHA256SUMS. Extract the release again from a verified archive.'
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const [root,...files]=process.argv.slice(2);const sums=new Map();
for(const line of fs.readFileSync(path.join(root,'SHA256SUMS'),'utf8').split('\n')){const m=/^([0-9a-f]{64}) [ *](.+)$/.exec(line);if(m)sums.set(m[2],m[1]);}
let bad=0;for(const file of files){const actual=crypto.createHash('sha256').update(fs.readFileSync(path.join(root,file))).digest('hex');if(sums.get(file)!==actual){console.error(`${file}: ${sums.has(file)?'checksum mismatch':'not listed in SHA256SUMS'}`);bad++;}}
process.exit(bad?1:0);
NODE
fi
# Check --trust-proxy with Uptime Goblin's own parser before anything on this host changes.
if [[ -n $goblin_trust_proxy ]]; then
  "$goblin_node" --input-type=module -e 'const { trustedProxies } = await import(process.argv[1]); trustedProxies(process.argv[2]);' "$goblin_source/lib/throttle.mjs" "$goblin_trust_proxy" || goblin_fail 'Invalid --trust-proxy value: use loopback, or proxy addresses/CIDR ranges.' 2
fi
# --listen and --allowed-hosts by Uptime Goblin's own rules too (lib/environment.mjs): HOST it would
# refuse, or a host entry no request can match (goblin.example/, https://…), is refused here.
"$goblin_node" --input-type=module -e 'const { allowedHostList, listenHost } = await import(process.argv[1]); try { listenHost(process.argv[2]); const { warnings } = allowedHostList(process.argv[3]); if (warnings.length) throw new Error(warnings.join("\n")); } catch (error) { console.error(error.message); process.exit(1); }' "$goblin_source/lib/environment.mjs" "$goblin_host" "$goblin_hosts" || goblin_fail 'Invalid --listen or --allowed-hosts value.' 2
# One installer run at a time: two runs share /opt/uptime-goblin.new, /opt/uptime-goblin.previous and
# /opt/uptime-goblin.failed, and their stops, moves and rollbacks would interleave. Taken before the
# installed release is read and before anything on this host changes, and held (descriptor 9)
# until the script exits. flock comes with util-linux, as runuser does; the tests put a stand-in
# on PATH (test/installer/fake-bin/flock).
command -v flock >/dev/null 2>&1 || goblin_fail 'flock (from util-linux) is required: install util-linux, then run this again.'
exec 9>"$goblin_root/run/uptime-goblin-install.lock" || goblin_fail "Could not open $goblin_root/run/uptime-goblin-install.lock for the installer lock."
flock -n 9 || goblin_fail 'Another Uptime Goblin installer run is in progress on this host; wait for it to finish, then run this again. Nothing was changed.'
# An Orbit installer (before 1.5) takes its own lock, /run/orbit-install.lock: held too (descriptor
# 8), so that no run of it can change the Orbit layout while this one reads or migrates it.
exec 8>"$goblin_root/run/orbit-install.lock" || goblin_fail "Could not open $goblin_root/run/orbit-install.lock for the installer lock."
flock -n 8 || goblin_fail 'An Orbit installer run is in progress on this host; wait for it to finish, then run this again. Nothing was changed.'
# The Orbit layout (see the start). goblin_migration ACTION runs the migration script below with
# this host's root: `detect` prints the layout (current: Uptime Goblin's own, or nothing installed
# yet; orbit: the Orbit layout, to migrate; interrupted: a migration under way that a run did not
# finish) and refuses, changing nothing, a host with parts of both layouts and no record of a
# migration; `check` refuses, changing nothing, an Orbit layout that cannot be moved by renames
# alone (below); `forward` migrates, writing the record first and each step's result as it goes;
# `reverse rollback|recover` restores the Orbit layout from the record and the files, step by
# step, whatever part of the migration and of the upgrade after it was done, then removes the
# record (rollback starts orbit.service again; recover only where it was running before); `done`
# removes the record once the upgrade is verified. Every step checks what is already done, so
# each action can be run again after it was cut short. The script prints its steps with the old
# and the new names (it runs without the message mapping of the checks, goblin_layout=raw).
# (No comments inside the block below: bash 3.2 reads a here-document for quotes in some places.)
goblin_migration_script() {
  printf '%s\n' "${goblin_env_js-}"
  cat <<'NODE'
const fs=require('node:fs'),path=require('node:path'),{spawnSync}=require('node:child_process');
const [action,root,mode]=process.argv.slice(2);
const at=p=>root+p;
const OLD={app:'/opt/orbit',data:'/var/lib/orbit',env:'/etc/orbit.env',key:'/etc/orbit',dropins:'/etc/systemd/system/orbit.service.d',unit:'/etc/systemd/system/orbit.service'};
const NEW={app:'/opt/uptime-goblin',data:'/var/lib/uptime-goblin',env:'/etc/uptime-goblin.env',key:'/etc/uptime-goblin',dropins:'/etc/systemd/system/uptime-goblin.service.d',unit:'/etc/systemd/system/uptime-goblin.service'};
const PATHS=[['/etc/orbit.env','/etc/uptime-goblin.env',true],['/etc/orbit','/etc/uptime-goblin'],['/var/lib/orbit','/var/lib/uptime-goblin'],['/opt/orbit','/opt/uptime-goblin']];
const newPath=v=>{for(const [old,now,exact] of PATHS)if(v===old||(!exact&&v.startsWith(old+'/')))return now+v.slice(old.length);return null;};
const journal=at('/var/lib/uptime-goblin.migrating');
const nothing='Nothing was changed.';
const exists=p=>{try{fs.lstatSync(at(p));return true;}catch(e){if(e.code==='ENOENT'||e.code==='ENOTDIR')return false;throw e;}};
const run=(cmd,args)=>spawnSync(cmd,args,{encoding:'utf8',stdio:['ignore','pipe','pipe']});
const said=r=>r.error?`could not be run (${r.error.code})`:`exited with status ${r.status}${String(r.stderr||'').trim()?`: ${String(r.stderr).replace(/\s+/g,' ').trim().slice(0,300)}`:''}`;
const passwd=name=>{const r=run('getent',['passwd',name]);return r.status===0&&r.stdout.trim()?r.stdout.trim().split('\n')[0].split(':'):null;};
const hasGroup=name=>{const r=run('getent',['group',name]);return r.status===0&&Boolean(r.stdout.trim());};
const hasCommand=name=>run('sh',['-c',`command -v ${name}`]).status===0;
const log=line=>console.log(line);
const syncDir=dir=>{try{const fd=fs.openSync(dir,'r');try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}catch{}};
const rename=(from,to)=>{
  if(exists(to))throw new Error(`${to} is already there`);
  try{fs.renameSync(at(from),at(to));}catch(e){throw new Error(e.code==='EXDEV'?`${from} cannot be renamed to ${to}: they are on different file systems`:`${from} could not be renamed to ${to} (${e.code||e.message})`);}
  syncDir(path.dirname(at(to)));
};
const readJournal=()=>{let text;try{text=fs.readFileSync(journal,'utf8');}catch(e){if(e.code==='ENOENT')return null;throw e;}const j=JSON.parse(text);if(!j||j.version!==1||typeof j.had!=='object')throw new Error('not a record this installer wrote');return j;};
const writeJournal=j=>{const tmp=journal+'.tmp';fs.rmSync(tmp,{force:true});fs.writeFileSync(tmp,JSON.stringify(j)+'\n',{mode:0o600,flag:'wx'});const fd=fs.openSync(tmp,'r');try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}fs.renameSync(tmp,journal);syncDir(path.dirname(journal));};
const convertEnv=bytes=>{
  const lines=envLines(bytes.toString('utf8'));if(lines.at(-1)==='')lines.pop();
  const errors=[],renamed=[];
  const out=lines.map((line,i)=>{
    const a=envAssignment(line);
    if(!a||!/^(ORBIT|GOBLIN)_/.test(a.key))return line;
    const key=a.key.replace(/^ORBIT_/,'GOBLIN_');
    let next=a.key===key?line:line.replace(/^([ \t]*)ORBIT_/,'$1GOBLIN_');
    if(a.key!==key)renamed.push(a.key);
    const value=newPath(a.value);
    if(value!==null){
      if(!/^[A-Za-z0-9._/:@%+,=-]+$/.test(value))errors.push(`${a.key} on line ${i+1} of /etc/orbit.env names a path in the Orbit layout with characters this installer does not rewrite: write it as a plain path (sudoedit /etc/orbit.env)`);
      next=`${key}=${value}`;
    }
    if(envAssignment(next)?.key!==key)errors.push(`line ${i+1} of /etc/orbit.env could not be rewritten`);
    return next;
  });
  return {text:out.join('\n')+'\n',errors,renamed};
};
const oldItems=()=>Object.values(OLD).filter(exists);
if(action==='detect'){
  if(fs.existsSync(journal)){process.stdout.write('interrupted');process.exit(0);}
  const old=oldItems();
  if(!old.length){process.stdout.write('current');process.exit(0);}
  const found=[NEW.app,NEW.app+'.previous',NEW.app+'.reinstall',NEW.data,NEW.env,NEW.key,NEW.dropins,NEW.unit].filter(exists);
  if(passwd('uptime-goblin'))found.push('the account uptime-goblin');
  if(hasGroup('uptime-goblin'))found.push('the group uptime-goblin');
  if(found.length){console.error(`This host has parts of both the Orbit layout (${old.join(', ')}) and the Uptime Goblin one (${found.join(', ')}), and no record of a migration under way (/var/lib/uptime-goblin.migrating), so this installer cannot tell which of them Uptime Goblin should use. If an earlier run moved this installation to the Uptime Goblin layout, the Orbit files are left over: check what each holds, move the ones that are not in use out of the way (for example to /root/orbit-leftovers), then run this installer again. ${nothing}`);process.exit(1);}
  process.stdout.write('orbit');process.exit(0);
}
if(action==='check'){
  const problems=[];
  for(const [name,p] of Object.entries(OLD)){
    if(!exists(p))continue;
    const s=fs.lstatSync(at(p)),target=name==='unit'?p+'.migrated':NEW[name];
    if(s.isSymbolicLink()){problems.push(`${p} is a symbolic link: the migration renames the files themselves and never follows a link. Put what it points to in its place, then run this installer again.`);continue;}
    const parent=fs.statSync(path.dirname(at(p))),destination=fs.statSync(path.dirname(at(target)));
    if(s.dev!==parent.dev)problems.push(`${p} is a mount point (another file system than ${path.dirname(p)}), which cannot be renamed to ${target}. Mount it at ${target} instead (and update /etc/fstab or its mount unit), then run this installer again.`);
    else if(s.dev!==destination.dev)problems.push(`${p} and ${path.dirname(target)} are on different file systems, so ${p} cannot be renamed to ${target}, and this installer never copies it. Move it yourself while Orbit is stopped, or make ${path.dirname(target)} part of the same file system, then run this installer again.`);
  }
  for(const p of [OLD.env+'.migrated',OLD.unit+'.migrated'])if(exists(p))problems.push(`${p} is already there, and the migration keeps the old file under that name. Move it out of the way, then run this installer again.`);
  const user=passwd('orbit');
  if(user&&user[5]!=='/opt/orbit')problems.push(`The account orbit has the home directory ${JSON.stringify(user[5]).slice(0,80)}, not /opt/orbit, so it is not the one the Orbit installer made, and this installer does not rename it. Rename it yourself if it is Orbit's (sudo usermod -l uptime-goblin -d /opt/uptime-goblin orbit && sudo groupmod -n uptime-goblin orbit), or remove the Orbit files, then run this installer again.`);
  if(user&&!hasCommand('usermod'))problems.push('usermod (from passwd) is needed to rename the account orbit.');
  if(hasGroup('orbit')&&!hasCommand('groupmod'))problems.push('groupmod (from passwd) is needed to rename the group orbit.');
  const shown=run('systemctl',['show','orbit.service','--property=LoadState,DropInPaths']);
  if(shown.error||shown.status!==0)problems.push(`systemctl show orbit.service ${said(shown)}.`);
  else{
    const props=new Map(shown.stdout.split('\n').filter(l=>l.includes('=')).map(l=>[l.slice(0,l.indexOf('=')),l.slice(l.indexOf('=')+1)]));
    const elsewhere=props.get('LoadState')==='loaded'?String(props.get('DropInPaths')||'').split(' ').filter(f=>f.includes('/orbit.service.d/')&&!f.startsWith(OLD.dropins+'/')):[];
    if(elsewhere.length)problems.push(`orbit.service has drop-ins that the migration does not move (${elsewhere.slice(0,5).join(', ')}): only those in ${OLD.dropins} are moved, to ${NEW.dropins}. Move them there, or remove them, then run this installer again.`);
  }
  if(exists(OLD.dropins)&&fs.lstatSync(at(OLD.dropins)).isDirectory())for(const name of fs.readdirSync(at(OLD.dropins)).sort()){
    if(!name.endsWith('.conf'))continue;
    let text='';try{text=fs.readFileSync(at(`${OLD.dropins}/${name}`),'latin1');}catch{continue;}
    const named=PATHS.map(([old])=>old).filter(old=>new RegExp(`${old.replace(/[.\/]/g,'\\$&')}(?![\\w.-])`).test(text));
    if(named.length)problems.push(`The drop-in ${OLD.dropins}/${name} names ${named.join(', ')}, which the migration moves. Remove that from it (sudo systemctl edit orbit), then run this installer again; once Uptime Goblin runs, add it back with the new path (sudo systemctl edit uptime-goblin).`);
  }
  if(exists(OLD.env)){const {errors}=convertEnv(fs.readFileSync(at(OLD.env)));problems.push(...errors.map(e=>e+'.'));}
  if(problems.length){console.error(`This installation cannot be moved from the Orbit layout to the Uptime Goblin one: ${problems.join(' ')} ${nothing}`);process.exit(1);}
  process.exit(0);
}
if(action==='forward'){
  if(fs.existsSync(journal)){console.error(`${journal.slice(root.length)} is already there. Run this installer again: it first undoes the migration that record describes.`);process.exit(1);}
  const had={app:exists(OLD.app),data:exists(OLD.data),env:exists(OLD.env),key:exists(OLD.key),dropins:exists(OLD.dropins),unit:exists(OLD.unit),user:Boolean(passwd('orbit')),group:hasGroup('orbit')};
  const j={version:1,started:new Date().toISOString(),had,enabled:had.unit&&run('systemctl',['is-enabled','--quiet','orbit.service']).status===0,active:had.unit&&run('systemctl',['is-active','--quiet','orbit.service']).status===0,done:[]};
  writeJournal(j);
  log('Moving this installation from the Orbit layout to the Uptime Goblin one (record: /var/lib/uptime-goblin.migrating, until the upgrade is verified):');
  const step=(name,fn)=>{fn();j.done.push(name);writeJournal(j);};
  try{
    step('stop',()=>{if(!had.unit)return;const r=run('systemctl',['stop','orbit.service']);if(r.error||r.status!==0)throw new Error(`systemctl stop orbit.service ${said(r)}`);log('  Stopped orbit.service.');});
    step('data',()=>{if(!had.data)return;rename(OLD.data,NEW.data);log(`  Renamed ${OLD.data} to ${NEW.data}.`);});
    step('env',()=>{
      if(!had.env)return;
      if(!exists(NEW.env)){
        const {text,errors,renamed}=convertEnv(fs.readFileSync(at(OLD.env)));
        if(errors.length)throw new Error(errors.join('; '));
        const tmp=at(NEW.env+'.goblin-tmp');fs.rmSync(tmp,{force:true});
        fs.writeFileSync(tmp,text,{mode:0o600,flag:'wx'});fs.chmodSync(tmp,0o600);
        const fd=fs.openSync(tmp,'r');try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
        fs.renameSync(tmp,at(NEW.env));syncDir(path.dirname(at(NEW.env)));
        log(`  Wrote ${NEW.env} from ${OLD.env}${renamed.length?` (${renamed.length} ORBIT_ ${renamed.length===1?'name':'names'} written as GOBLIN_)`:''}, mode 0600.`);
      }
      rename(OLD.env,OLD.env+'.migrated');log(`  Kept ${OLD.env} as ${OLD.env}.migrated.`);
    });
    step('key',()=>{if(!had.key)return;rename(OLD.key,NEW.key);log(`  Renamed ${OLD.key} to ${NEW.key}.`);});
    step('account',()=>{
      if(had.user&&passwd('orbit')){const r=run('usermod',['-l','uptime-goblin','-d','/opt/uptime-goblin','orbit']);if(r.error||r.status!==0)throw new Error(`usermod -l uptime-goblin orbit ${said(r)}`);log('  Renamed the account orbit to uptime-goblin.');}
      if(had.group&&hasGroup('orbit')){const r=run('groupmod',['-n','uptime-goblin','orbit']);if(r.error||r.status!==0)throw new Error(`groupmod -n uptime-goblin orbit ${said(r)}`);log('  Renamed the group orbit to uptime-goblin.');}
    });
    step('dropins',()=>{if(!had.dropins)return;rename(OLD.dropins,NEW.dropins);log(`  Renamed ${OLD.dropins} to ${NEW.dropins}.`);});
    step('unit',()=>{
      if(!had.unit)return;
      const r=run('systemctl',['disable','--quiet','orbit.service']);if(r.error||r.status!==0)throw new Error(`systemctl disable orbit.service ${said(r)}`);
      rename(OLD.unit,OLD.unit+'.migrated');log(`  Disabled orbit.service and kept its unit file as ${OLD.unit}.migrated.`);
    });
    step('app',()=>{if(!had.app)return;rename(OLD.app,NEW.app);log(`  Renamed ${OLD.app} to ${NEW.app}.`);});
  }catch(e){console.error(`The migration from the Orbit layout stopped: ${e.message}.`);process.exit(1);}
  process.exit(0);
}
if(action==='reverse'){
  let j;
  try{j=readJournal();}catch(e){console.error(`/var/lib/uptime-goblin.migrating cannot be read (${e.code||e.message}), so this installer cannot tell what the migration from the Orbit layout changed. Compare the Orbit and the Uptime Goblin paths (see the start of deploy/install.sh) and put them back by hand; then remove that file and run this installer again.`);process.exit(1);}
  if(!j){console.error('There is no record of a migration from the Orbit layout to undo (/var/lib/uptime-goblin.migrating).');process.exit(1);}
  const had=j.had;
  log('Restoring the Orbit layout:');
  const back=(from,to)=>{if(exists(to)||!exists(from))return false;rename(from,to);log(`  Renamed ${from} back to ${to}.`);return true;};
  try{
    if(exists(NEW.unit)){
      run('systemctl',['stop','uptime-goblin.service']);
      const r=run('systemctl',['disable','--quiet','uptime-goblin.service']);if(r.error||r.status!==0)throw new Error(`systemctl disable uptime-goblin.service ${said(r)}`);
      fs.rmSync(at(NEW.unit));syncDir(path.dirname(at(NEW.unit)));log(`  Stopped and disabled uptime-goblin.service and removed ${NEW.unit}.`);
    }
    if(!exists(OLD.app)){
      const failed=NEW.app+'.failed';
      const aside=()=>{if(!exists(NEW.app))return;fs.rmSync(at(failed),{recursive:true,force:true});rename(NEW.app,failed);log(`  Kept the new release in ${failed} for diagnosis.`);};
      if(had.app&&exists(NEW.app+'.previous')){aside();rename(NEW.app+'.previous',OLD.app);log(`  Renamed ${NEW.app}.previous back to ${OLD.app}.`);}
      else if(had.app&&exists(NEW.app)){rename(NEW.app,OLD.app);log(`  Renamed ${NEW.app} back to ${OLD.app}.`);}
      else if(!had.app)aside();
    }
    if(had.unit&&!exists(OLD.unit)&&exists(OLD.unit+'.migrated')){rename(OLD.unit+'.migrated',OLD.unit);log(`  Renamed ${OLD.unit}.migrated back to ${OLD.unit}.`);}
    if(had.dropins)back(NEW.dropins,OLD.dropins);
    if(had.user&&!passwd('orbit')&&passwd('uptime-goblin')){const r=run('usermod',['-l','orbit','-d','/opt/orbit','uptime-goblin']);if(r.error||r.status!==0)throw new Error(`usermod -l orbit uptime-goblin ${said(r)}`);log('  Renamed the account uptime-goblin back to orbit.');}
    if(had.group&&!hasGroup('orbit')&&hasGroup('uptime-goblin')){const r=run('groupmod',['-n','orbit','uptime-goblin']);if(r.error||r.status!==0)throw new Error(`groupmod -n orbit uptime-goblin ${said(r)}`);log('  Renamed the group uptime-goblin back to orbit.');}
    if(had.key)back(NEW.key,OLD.key);
    if(had.env){
      if(!exists(OLD.env)&&exists(OLD.env+'.migrated')){rename(OLD.env+'.migrated',OLD.env);log(`  Renamed ${OLD.env}.migrated back to ${OLD.env}.`);}
      if(exists(OLD.env)&&exists(NEW.env)){
        if(j.restore){rename(NEW.env,NEW.env+'.kept');log(`  Kept ${NEW.env}, the settings Uptime Goblin ran with, as ${NEW.env}.kept.`);}
        else{fs.rmSync(at(NEW.env));syncDir(path.dirname(at(NEW.env)));log(`  Removed ${NEW.env}, written from it.`);}
      }
    }
    if(had.data)back(NEW.data,OLD.data);
  }catch(e){console.error(`The Orbit layout could not be restored: ${e.message}. Run this installer again, which goes on restoring it from /var/lib/uptime-goblin.migrating before anything else.`);process.exit(1);}
  const reload=run('systemctl',['daemon-reload']);
  if(reload.error||reload.status!==0)console.error(`WARNING: systemctl daemon-reload ${said(reload)}.`);
  let started=true;
  if(had.unit&&exists(OLD.unit)){
    if(j.enabled){const r=run('systemctl',['enable','--quiet','orbit.service']);if(r.error||r.status!==0)console.error(`WARNING: systemctl enable orbit.service ${said(r)}.`);}
    if((mode==='rollback'||j.active)&&exists(OLD.app+'/server.mjs')){const r=run('systemctl',['restart','orbit.service']);started=!r.error&&r.status===0;log(started?'  Started orbit.service again.':`  orbit.service could not be started: systemctl restart ${said(r)}.`);}
  }
  fs.rmSync(at(NEW.env+'.goblin-tmp'),{force:true});fs.rmSync(journal+'.tmp',{force:true});
  fs.rmSync(journal,{force:true});syncDir(path.dirname(journal));
  log('The Orbit layout is restored.');
  process.exit(started?0:2);
}
if(action==='restore-check'){
  const problems=[];
  const version=dir=>{try{return String(JSON.parse(fs.readFileSync(at(dir+'/package.json'),'utf8')).version||'');}catch{return '';}};
  const kept=NEW.app+'.previous',v=version(kept),m=/^(\d+)\.(\d+)\.\d+(?:[-+]|$)/.exec(v);
  if(!exists(kept+'/server.mjs'))problems.push(`There is no previous release in ${kept} to go back to.`);
  else if(!m||!(+m[1]<1||(+m[1]===1&&+m[2]<5)))problems.push(`${kept} holds ${v?`Uptime Goblin ${v}`:'a release whose version cannot be read'}, not an Orbit release (before 1.5), so this host was not moved from the Orbit layout by the upgrade that installed it, or a later upgrade replaced that copy.`);
  for(const p of [OLD.env+'.migrated',OLD.unit+'.migrated'])if(!exists(p))problems.push(`${p}, which the migration from the Orbit layout keeps, is not there (removed, or this host was never migrated), so the Orbit settings and unit cannot be put back.`);
  for(const p of [NEW.app+'/server.mjs',NEW.data,NEW.env,NEW.unit])if(!exists(p))problems.push(`${p} is not there: this is not a working Uptime Goblin installation.`);
  for(const p of [NEW.app+'.failed',NEW.env+'.kept'])if(exists(p))problems.push(`${p} is already there, and going back keeps ${p===NEW.env+'.kept'?'the current settings':'this release'} under that name. Move it out of the way, then run this installer again.`);
  if(passwd('orbit')||hasGroup('orbit'))problems.push('An account or group named orbit is already there, and the account uptime-goblin is renamed back to orbit.');
  const user=passwd('uptime-goblin');
  if(!user)problems.push('There is no account uptime-goblin to rename back to orbit.');
  else if(user[5]!=='/opt/uptime-goblin')problems.push(`The account uptime-goblin has the home directory ${JSON.stringify(user[5]).slice(0,80)}, not /opt/uptime-goblin, so it is not the one the migration renamed.`);
  if(user&&!hasCommand('usermod'))problems.push('usermod (from passwd) is needed to rename the account uptime-goblin back.');
  if(hasGroup('uptime-goblin')&&!hasCommand('groupmod'))problems.push('groupmod (from passwd) is needed to rename the group uptime-goblin back.');
  const moves=[[kept,OLD.app],[NEW.data,OLD.data],[NEW.key,OLD.key],[NEW.dropins,OLD.dropins],[OLD.env+'.migrated',OLD.env],[OLD.unit+'.migrated',OLD.unit],[NEW.env,NEW.env+'.kept'],[NEW.app,NEW.app+'.failed']];
  for(const [from,to] of moves){
    if(!exists(from))continue;
    const s=fs.lstatSync(at(from));
    if(s.isSymbolicLink()){problems.push(`${from} is a symbolic link: going back renames the files themselves and never follows a link.`);continue;}
    const parent=fs.statSync(path.dirname(at(from))),destination=fs.statSync(path.dirname(at(to)));
    if(s.dev!==parent.dev)problems.push(`${from} is a mount point (another file system than ${path.dirname(from)}), which cannot be renamed to ${to}.`);
    else if(s.dev!==destination.dev)problems.push(`${from} and ${path.dirname(to)} are on different file systems, so ${from} cannot be renamed to ${to}, and this installer never copies it.`);
  }
  if(exists(NEW.dropins)&&fs.lstatSync(at(NEW.dropins)).isDirectory())for(const name of fs.readdirSync(at(NEW.dropins)).sort()){
    if(!name.endsWith('.conf'))continue;
    let text='';try{text=fs.readFileSync(at(`${NEW.dropins}/${name}`),'latin1');}catch{continue;}
    const named=PATHS.map(([,now])=>now).filter(now=>new RegExp(`${now.replace(/[.\/]/g,'\\$&')}(?![\\w.-])`).test(text));
    if(named.length)problems.push(`The drop-in ${NEW.dropins}/${name} names ${named.join(', ')}, which Orbit does not have. Remove that from it (sudo systemctl edit uptime-goblin), then run this installer again.`);
  }
  if(problems.length){console.error(`This installation cannot go back to the Orbit layout: ${problems.join(' ')} ${nothing}`);process.exit(1);}
  process.stdout.write(v);process.exit(0);
}
if(action==='restore'){
  if(fs.existsSync(journal)){console.error(`${journal.slice(root.length)} is already there. Run this installer again: it first finishes what that record describes.`);process.exit(1);}
  const had={app:true,data:exists(NEW.data),env:true,key:exists(NEW.key),dropins:exists(NEW.dropins),unit:true,user:Boolean(passwd('uptime-goblin')),group:hasGroup('uptime-goblin')};
  writeJournal({version:1,started:new Date().toISOString(),restore:true,had,enabled:run('systemctl',['is-enabled','--quiet','uptime-goblin.service']).status===0,active:true,done:['stop','data','env','key','account','dropins','unit','app']});
  process.exit(0);
}
if(action==='done'){fs.rmSync(journal,{force:true});syncDir(path.dirname(journal));process.exit(0);}
console.error(`goblin_migration: unknown action ${action}`);process.exit(64);
NODE
}
# Run with every signal ignored (as goblin_shield runs a command), so that no step is cut short.
goblin_migration() {
  (
    trap '' HUP INT TERM
    goblin_migration_script | goblin_layout=raw "$goblin_node" - "$1" "$goblin_root" "${2-}"
  )
}
goblin_layout=$(goblin_migration detect) || exit 1
# Going back to Orbit (see the start): the checks, then the migration's own rollback from a record
# of everything the migration did, so a run cut short is finished by the next one (detect then
# says interrupted, and this goes on with the rollback). It installs nothing.
if [[ -n $goblin_restore ]]; then
  [[ $goblin_layout != orbit ]] || goblin_fail 'This host has the Orbit layout already, so there is nothing to go back from. Nothing was changed.'
  if [[ $goblin_layout == interrupted ]]; then
    printf 'An earlier run of this installer was cut short while it moved this installation between the Orbit layout and the Uptime Goblin one (/var/lib/uptime-goblin.migrating). Finishing the move back to the Orbit layout.\n' >&2
  else
    goblin_restore_version=$(goblin_migration restore-check) || exit 1
    printf 'Going back to Orbit %s, kept in /opt/uptime-goblin.previous, with the Orbit layout.\n' "$goblin_restore_version"
    goblin_migration restore || goblin_fail 'Nothing was changed.'
  fi
  goblin_status=0
  goblin_migration reverse rollback || goblin_status=$?
  ((goblin_status != 1)) || goblin_fail 'The Orbit layout could not be restored (above). Run this installer again with --restore-orbit-layout: it goes on from where this run stopped.'
  ((goblin_status != 2)) || goblin_fail 'The Orbit layout is restored, but orbit.service could not be started. Check: journalctl -u orbit.service'
  goblin_restore_version=$("$goblin_node" -p 'String(require(process.argv[1]).version||"")' "$legacy_app/package.json" 2>/dev/null || true)
  goblin_restore_build=$("$goblin_node" "$goblin_source/lib/healthcheck.mjs" --print-build "$legacy_app" 2>/dev/null || true)
  goblin_restored="Orbit $goblin_restore_version runs again from /opt/orbit as orbit.service, on /var/lib/orbit with /etc/orbit.env. The settings Uptime Goblin ran with are kept as /etc/uptime-goblin.env.kept, and Uptime Goblin in /opt/uptime-goblin.failed; remove them once you no longer need them. The next upgrade moves this installation to the Uptime Goblin layout again."
  # Releases before 1.4.3 have no process-nonce contract: their own health check, bounded as below.
  if "$goblin_node" -e 'const m=/^(\d+)\.(\d+)\.(\d+)(?:-|$)/.exec(process.argv[1]); process.exit(m && +m[1]===1 && (+m[2]<4 || (+m[2]===4 && +m[3]<3)) ? 0 : 1)' "$goblin_restore_version"; then
    if "$goblin_node" - "$goblin_verify_timeout" "$legacy_env" "$legacy_app/lib/healthcheck.mjs" <<'NODE'
const {spawnSync}=require('node:child_process');
const seconds=Number(process.argv[2]);
const result=spawnSync(process.execPath,[`--env-file=${process.argv[3]}`,process.argv[4],'--wait'],{stdio:'inherit',timeout:seconds*1000,killSignal:'SIGKILL'});
process.exitCode=result.status===0&&!result.error?0:1;
NODE
    then
      printf '%s Its legacy health check answered; its process identity is unverified, so confirm with systemctl status orbit.service.\n' "$goblin_restored"
      exit 0
    fi
    goblin_fail "The Orbit layout is restored, but the legacy health check of Orbit $goblin_restore_version did not pass. Check: journalctl -u orbit.service"
  fi
  if "$goblin_node" --env-file="$legacy_env" "$goblin_source/lib/healthcheck.mjs" --wait --timeout "$goblin_verify_timeout" --data-dir "$legacy_data" --expect-version "$goblin_restore_version" --expect-build "$goblin_restore_build" --unit orbit.service; then
    printf '%s\n' "$goblin_restored"
    exit 0
  fi
  goblin_fail "The Orbit layout is restored and orbit.service was started, but Orbit $goblin_restore_version could not be verified as serving. Check: journalctl -u orbit.service"
fi
if [[ $goblin_layout == interrupted ]]; then
  printf 'An earlier run of this installer was cut short while it moved this installation from the Orbit layout to the Uptime Goblin one (/var/lib/uptime-goblin.migrating). Restoring the Orbit layout first; this run then migrates again.\n' >&2
  goblin_status=0
  goblin_migration reverse recover || goblin_status=$?
  ((goblin_status == 0 || goblin_status == 2)) || goblin_fail 'Nothing else was changed.'
  goblin_layout=$(goblin_migration detect) || exit 1
fi
if [[ $goblin_layout == orbit ]]; then
  goblin_cur_app=$legacy_app goblin_cur_data=$legacy_data goblin_cur_env=$legacy_env
  goblin_cur_key_home=$legacy_key_home goblin_cur_unit=$legacy_unit goblin_service=orbit.service
  goblin_account=orbit goblin_env_prefix=ORBIT_
  printf 'This host has the Orbit layout (%s): the upgrade moves it to the Uptime Goblin layout after the checks below, in place of the service stop.\n' "${legacy_unit#"$goblin_root"}, /opt/orbit, /var/lib/orbit, /etc/orbit.env"
else
  goblin_cur_app=$goblin_app goblin_cur_data=$goblin_data goblin_cur_env=$goblin_env
  goblin_cur_key_home=$goblin_key_home goblin_cur_unit=$goblin_unit goblin_service=uptime-goblin.service
  goblin_account=uptime-goblin goblin_env_prefix=GOBLIN_
fi
# The checks below read the files where they are now and name them so: before the migration, each
# message that names an Uptime Goblin path, unit or account names the Orbit one (layoutText()).
export goblin_layout goblin_account goblin_env_prefix goblin_service
# The release installed now, if any (empty for a new install): the proxy preflight below and
# the closing message depend on whether this is the upgrade from 1.4.x to 1.5.
goblin_installed_version=
if [[ -f $goblin_cur_app/package.json ]]; then
  goblin_installed_version=$("$goblin_node" -p 'String(require(process.argv[1]).version||"")' "$goblin_cur_app/package.json" 2>/dev/null || true)
fi
# An installed tree whose version cannot be read cannot be compared either: warn, as below.
if [[ -e $goblin_cur_app && -z $goblin_installed_version ]]; then
  printf 'WARNING: %s has no readable release version (package.json missing, unreadable or without one), so this installer cannot tell whether Uptime Goblin %s is older. Going on.\n' "$goblin_cur_app" "$("$goblin_node" -p 'String(require(process.argv[1]).version||"")' "$goblin_source/package.json")" >&2
fi
goblin_new_version=$("$goblin_node" -p 'String(require(process.argv[1]).version||"")' "$goblin_source/package.json")
# 1.x.y below 1.5.0 (a pre-release counts as its core release), for the version given.
goblin_before_15() {
  "$goblin_node" -e 'const m=/^(\d+)\.(\d+)\.(\d+)(?:[-+]|$)/.exec(process.argv[1]); process.exit(m && (+m[1]<1 || (+m[1]===1 && +m[2]<5)) ? 0 : 1)' "$1"
}
# An older release over a newer one is refused, changing nothing (exit status 2), unless
# --allow-downgrade is given: the newer copy would become /opt/uptime-goblin.previous and the older code
# would run on data the newer one may have changed, which Uptime Goblin itself refuses only for a contract
# step or a newer-release fence. Compared in Uptime Goblin's own order (compareReleases in
# lib/db/migrate.mjs). An installed version that does not parse as a release is warned about and
# the install goes on; a new version that does not parse is refused after staging, as before.
if [[ -n $goblin_installed_version ]]; then
  goblin_order=$("$goblin_node" --input-type=module -e 'const { parseRelease, compareReleases } = await import(process.argv[1]); const [next, installed] = process.argv.slice(2); const parses = value => { try { parseRelease(value); return true; } catch { return false; } }; process.stdout.write(!parses(installed) ? "installed-unknown" : !parses(next) ? "new-unknown" : compareReleases(next, installed) < 0 ? "older" : "not-older");' "$goblin_source/lib/db/migrate.mjs" "$goblin_new_version" "$goblin_installed_version") || goblin_fail 'Could not compare the release being installed with the installed one.'
  case $goblin_order in
    older)
      if [[ -n $goblin_allow_downgrade ]]; then
        printf 'WARNING: --allow-downgrade: installing Uptime Goblin %s over the newer Uptime Goblin %s. The older release runs on data the newer one may have changed; restore that data from before the upgrade first (goblin-admin restore-snapshot, or a backup: see "Updates and rollback" in docs/installation.md).\n' "$goblin_new_version" "$goblin_installed_version" >&2
      else
        goblin_fail "Uptime Goblin $goblin_installed_version is installed, and this release, $goblin_new_version, is older. Nothing was changed. Installing it would run older code on data the newer release may have changed. To go back to an earlier release, restore the data from before the upgrade (goblin-admin restore-snapshot, or a backup) and swap the code as \"Updates and rollback\" in docs/installation.md describes; to install this release over the newer one anyway, run this installer again with --allow-downgrade." 2
      fi ;;
    installed-unknown)
      printf 'WARNING: the installed version (%q in %s/package.json) is not a release this installer can compare, so it cannot tell whether Uptime Goblin %s is older. Going on.\n' "$goblin_installed_version" "${goblin_cur_app#"$goblin_root"}" "$goblin_new_version" >&2 ;;
  esac
fi
# /etc/uptime-goblin.env as systemd's EnvironmentFile= reads it, for the steps below that judge or change
# its values; each prepends this to its script. envRead() runs a copy of systemd's own parser
# (parse_env_file_internal() in src/basic/env-file.c) over the file's bytes, with the checks
# systemd makes around it; compared with systemd 257 (Debian 13) when it was written. A line ends
# at LF or CR (CRLF is a line end and an empty line); spaces and tabs, and no other character, are
# blanks around the name, the = and the value; a line starting with # or ; is a comment; outside
# quotes a backslash takes the next character as it is; '…' and "…" quote any part of a value
# (in "…" a backslash escapes only a double quote, a backslash, a backquote and $), so "43"17 is
# 4317; a name of anything but ASCII letters, digits and _, or one starting with a digit
# (`export PORT`), is dropped; and the last assignment of a name is the one Uptime Goblin gets, and the
# one an update must rewrite. systemd refuses to read a file
# that holds a NUL or a name or value that is not UTF-8 (or holds a noncharacter such as U+FFFF),
# and then does not start Uptime Goblin. A quote not closed at the end of its line, or a backslash at the
# end of a line, joins the next line on to the value, and a comment line ending in a backslash
# joins the next line to the comment in systemd before version 254 (Debian 12 has 252), but not
# in 257. The steps that rewrite the file do it line by line, so the check below refuses, before
# anything changes, a file in which a value or a comment runs on past the end of its line.
# envRead(input) returns `values`, what systemd passes Uptime Goblin (a name not set is absent);
# `joined`, each place where a value or a comment runs on past the end of a line ({line, state},
# lines counted from 0 as envLines() splits them, also the last line of a file that ends open
# without a line end, after which an added line would join); and `refused`, why systemd would not
# read the file at all ({line, why}: 'nul' or 'utf8'). envUtf8() is systemd's utf8_is_valid() on a
# string of bytes: sequences of 1 to 6 bytes, none longer than its value needs, and no value past
# U+10FFFF, of a UTF-16 surrogate or a noncharacter (U+FDD0 to U+FDEF, the last two of each
# plane). envAssignment() reads one line alone, for the steps that rewrite the file line by line.
# (No comments inside the block below: bash 3.2, which runs the tests on macOS, reads the text
# of a here-document inside $(…) for quotes, so an apostrophe or a backquote there breaks the
# script.)
# (The update step once read the first assignment: with HOST=0.0.0.0 appended below
# HOST=127.0.0.1 it judged the install loopback, and 1.5 then refused plain-HTTP sign-in. Then,
# reading each line on its own: a line ending in CRLF matched no assignment at all; a value
# ending in a vertical tab or a no-break space was read without it, which systemd passes as it
# is; and the line after an open quote or a final backslash was read as a setting of its own.)
#
# Also shared: shellWord(), which quotes a path for a command line printed to paste (a key file
# named with a space or a shell character would otherwise print a line that does something
# else), and proxyOn(), whether a GOBLIN_TRUST_PROXY value names a proxy by Uptime Goblin's own parser
# (off, 0, false and no do not; a value Uptime Goblin refuses counts as one, as any value used to, but
# none reaches it: the checks below refuse such a value before the steps that ask proxyOn()).
# envPreReleaseOptIn(lines) finds, in the lines of /etc/uptime-goblin.env as envLines() splits them, the
# GOBLIN_INSECURE_HTTP_SESSIONS=1 that installers of earlier 1.5 pre-releases added by themselves
# to an install that listened on the network without a trusted proxy: the last assignment of that
# name says 1 and the line just before it is exactly the comment they wrote with it
# (envPreReleaseComment). It returns the index of that comment, or -1. Such a line was no one's
# choice: the plain-HTTP step below stops every install that has one, changing nothing, until it
# is decided (either line edited) or --allow-insecure-http records it as a choice. A =1 without
# that comment just before it is a decision.
goblin_env_js=$(cat <<'NODE'
const shellWord=word=>/^[A-Za-z0-9._/:=@%+,-]+$/.test(word)?word:"'"+String(word).split("'").join("'\\''")+"'";
const proxyOn=(value,source)=>{try{return require(require('node:path').join(source,'lib/throttle.mjs')).trustedProxies(value)!==null;}catch{return Boolean(String(value??'').trim());}};
const envLines=text=>text.split(/\r\n|\r|\n/);
const envName=key=>/^[A-Za-z_][A-Za-z0-9_]*$/.test(key);
const envUtf8=s=>{for(let i=0;i<s.length;){const b=s.charCodeAt(i),n=b<0x80?1:b>>5===6?2:b>>4===14?3:b>>3===30?4:b>>2===62?5:b>>1===126?6:0;if(!n||i+n>s.length)return false;let u=n===1?b:b&(0x7f>>n);for(let k=1;k<n;k++){const x=s.charCodeAt(i+k);if(x>>6!==2)return false;u=u*64+(x&63);}if(n!==(u<0x80?1:u<0x800?2:u<0x10000?3:u<0x200000?4:u<0x4000000?5:6)||u>=0x110000||(u>=0xd800&&u<=0xdfff)||(u>=0xfdd0&&u<=0xfdef)||(u&0xfffe)===0xfffe)return false;i+=n;}return true;};
const envRead=input=>{
  const s=(Buffer.isBuffer(input)?input:Buffer.from(String(input))).toString('latin1'),nl=c=>c==='\n'||c==='\r',blank=c=>c===' '||c==='\t'||nl(c),plain=['preKey','key','preValue','value','comment'];
  const found=[],joined=[],refused=[];let state='preKey',key='',value=null,keyEnd=-1,valueEnd=-1,line=0,first=0;
  const add=c=>{value=(value??'')+c;};
  const push=chomp=>{if(chomp&&valueEnd>=0)value=value.slice(0,valueEnd);if(keyEnd>=0)key=key.slice(0,keyEnd);if(envUtf8(key)&&envUtf8(value??''))found.push({key:Buffer.from(key,'latin1').toString(),value:Buffer.from(value??'','latin1').toString(),line:first});else refused.push({line:first,why:'utf8'});key='';value=null;};
  for(let p=0;p<s.length;p++){
    const c=s[p],ends=c==='\r'||(c==='\n'&&s[p-1]!=='\r');
    if(c==='\0')refused.push({line,why:'nul'});
    if(ends&&!plain.includes(state))joined.push({line,state});
    if(state==='preKey'){if(c==='#'||c===';')state='comment';else if(!blank(c)){state='key';key=c;keyEnd=-1;first=line;}}
    else if(state==='key'){if(nl(c))state='preKey';else if(c==='='){state='preValue';valueEnd=-1;}else{if(!blank(c))keyEnd=-1;else if(keyEnd<0)keyEnd=key.length;key+=c;}}
    else if(state==='preValue'){if(nl(c)){state='preKey';push(false);}else if(c==="'")state='single';else if(c==='"')state='double';else if(c==='\\')state='valueEscape';else if(!blank(c)){state='value';add(c);}}
    else if(state==='value'){if(nl(c)){state='preKey';push(true);}else if(c==='\\'){state='valueEscape';valueEnd=-1;}else{if(!blank(c))valueEnd=-1;else if(valueEnd<0)valueEnd=(value??'').length;add(c);}}
    else if(state==='valueEscape'){state='value';if(!nl(c))add(c);}
    else if(state==='single'){if(c==="'")state='preValue';else add(c);}
    else if(state==='double'){if(c==='"')state='preValue';else if(c==='\\')state='doubleEscape';else add(c);}
    else if(state==='doubleEscape'){state='double';if(['"','\\','\x60','$'].includes(c))add(c);else if(c!=='\n')add('\\'+c);}
    else if(state==='comment'){if(c==='\\')state='commentEscape';else if(nl(c))state='preKey';}
    else state=nl(c)?'preKey':'comment';
    if(ends)line++;
  }
  if(!plain.includes(state)&&!nl(s.at(-1)))joined.push({line,state});
  if(['preValue','value','valueEscape','single','double','doubleEscape'].includes(state))push(state==='value');
  const values=Object.create(null);for(const a of found)if(envName(a.key))values[a.key]=a.value;
  return {values,found,joined,refused};
};
const envValues=input=>envRead(input).values;
const envAssignment=line=>{const a=envRead(line).found[0];return a&&envName(a.key)?a:null;};
const envLastLine=(lines,key)=>{for(let i=lines.length-1;i>=0;i--)if(envAssignment(lines[i])?.key===key)return i;return -1;};
const envPreReleaseComment="# Added by the Orbit 1.5 installer: keeps plain-HTTP sign-in working as in 1.4.x. Set it to 0 once Orbit is served over HTTPS.";
const envCurrentLine=(lines,key)=>{const i=envLastLine(lines,key);return i>=0||!key.startsWith('GOBLIN_')?i:envLastLine(lines,'ORBIT_'+key.slice(7));};
const envPreReleaseOptIn=lines=>{const i=envCurrentLine(lines,"GOBLIN_INSECURE_HTTP_SESSIONS");return i>0&&envAssignment(lines[i]).value==="1"&&lines[i-1]===envPreReleaseComment?i-1:-1;};
const envCurrent=values=>{const out=Object.create(null),conflicts=[];for(const [k,v] of Object.entries(values))if(!k.startsWith('ORBIT_'))out[k]=v;for(const [k,v] of Object.entries(values))if(k.startsWith('ORBIT_')){const n='GOBLIN_'+k.slice(6);if(n in out){if(out[n]!==v&&!conflicts.includes(n))conflicts.push(n);}else out[n]=v;}return {values:out,conflicts};};
const envConflicts=names=>names.map(n=>n+' and ORBIT_'+n.slice(7)).join(', ')+(names.length>1?' are each':' are both')+' set, to different values, so which was meant cannot be told: keep the GOBLIN_ '+(names.length>1?'names':'name')+' and remove the ORBIT_ '+(names.length>1?'ones':'one');
const layoutOld=process.env.goblin_layout==='orbit';
const layoutNames=[['/etc/uptime-goblin.env','/etc/orbit.env'],['/etc/uptime-goblin','/etc/orbit'],['/var/lib/uptime-goblin','/var/lib/orbit'],['/opt/uptime-goblin','/opt/orbit'],['uptime-goblin.service','orbit.service'],['systemctl edit uptime-goblin','systemctl edit orbit'],['systemctl start uptime-goblin','systemctl start orbit'],['systemctl stop uptime-goblin','systemctl stop orbit'],['systemctl restart uptime-goblin','systemctl restart orbit'],['journalctl -u uptime-goblin','journalctl -u orbit'],['root:uptime-goblin','root:orbit'],['uptime-goblin:uptime-goblin','orbit:orbit'],['-u uptime-goblin','-u orbit'],['uptime-goblin account','orbit account'],['group uptime-goblin','group orbit'],['account uptime-goblin','account orbit']];
const layoutPath=p=>{if(!layoutOld)return p;for(const [now,old] of layoutNames.slice(0,4))if(p===now||(now!=='/etc/uptime-goblin.env'&&p.startsWith(now+'/')))return old+p.slice(now.length);return p;};
const layoutText=s=>layoutOld?layoutNames.reduce((t,[now,old])=>t.split(now).join(old),s):s;
if(layoutOld)for(const k of ['log','warn','error']){const f=console[k].bind(console);console[k]=(...a)=>f(...a.map(x=>typeof x==='string'?layoutText(x):x));}
NODE
)
# First, a file systemd would not read at all (it then does not start Uptime Goblin: a NUL, or a name
# or value that is not UTF-8), and one in which a setting or a comment runs on into the next line
# (see envRead() above), are refused, changing nothing: every step below that rewrites
# /etc/uptime-goblin.env does it line by line, and a line it changed or added there could change, or
# become part of, the value that runs on. Read line by line, such a file also gave this check
# another HOST or PORT than systemd passes.
#
# Then HOST and PORT in /etc/uptime-goblin.env, as systemd passes them, by this release's own rules
# (lib/environment.mjs), GOBLIN_LEGACY_BASIC (lib/environment.mjs: a value that is neither yes nor
# no refuses the start), GOBLIN_ALLOW_UNLIMITED and GOBLIN_SUPERVISED (lib/resource-limits.mjs:
# a malformed list, or a value that is neither yes nor no, refuses the start), and
# GOBLIN_MAX_CONNECTIONS_PER_CLIENT and GOBLIN_TRUST_PROXY (lib/throttle.mjs: a number outside 8 to
# 256, a malformed entry, a range that trusts too many addresses or a value that names no proxy
# refuses the start; GOBLIN_TRUST_PROXY not when --trust-proxy, already checked above, replaces
# it), and GOBLIN_DISPLAY_SESSION_DAYS and GOBLIN_DISPLAY_IDLE_DAYS (lib/environment.mjs: days
# outside 1 to 30 and 1 to 7 refuse the start), before anything on this host changes. 1.4.x took values this release refuses (PORT=04317,
# which its Number() read as 4317; GOBLIN_TRUST_PROXY=0.0.0.0/0): the upgrade would stop Uptime Goblin,
# fail to start (exit status 78) and roll back, and with PORT the rollback could not be verified
# either, since the verifier is this release's healthcheck, which reads PORT by the same rule.
# Refused here instead, changing nothing. The healthcheck reads no other setting from the
# environment, so a rollback after another value this release refuses (more than 64
# GOBLIN_ALLOWED_HOSTS entries, say) is verified. The step after this one checks the same settings
# as systemd would give them to Uptime Goblin, for a drop-in or systemd's own environment can set them too.
#
# The healthcheck itself reads the file with node --env-file, whose parser (util.parseEnv) reads
# some lines otherwise than systemd: it drops a CR that no LF follows instead of ending the line
# there, takes `export PORT=…` for PORT (systemd ignores the line), ends a value at its closing
# quote and one without quotes at a #, takes a backquote for a quote and keeps a backslash
# outside quotes. Where the two readings of HOST or PORT give another address or port (or one
# this release refuses), the check after the start, and after a rollback, would not probe the one
# Uptime Goblin listens on: refused here too, changing nothing. The healthcheck runs without this
# installer's own HOST and PORT (unset at the top), so the file is all it reads them from. What
# systemd takes from elsewhere (drop-ins, its own environment) is compared in the next step.
# On a host with the Orbit layout, whether the migration can move it (goblin_migration check:
# symbolic links, mount points, file systems, an account or drop-ins it would not move), before
# anything changes.
if [[ $goblin_layout == orbit ]]; then
  goblin_migration check || exit 1
fi
if [[ -e $goblin_cur_env ]]; then
  {
    printf '%s\n' "$goblin_env_js"
    cat <<'NODE'
const fs=require('node:fs'),path=require('node:path'),{parseEnv}=require('node:util');
const [envFile,source,trustOption]=process.argv.slice(2);
const nothing='Nothing was changed.';
let bytes;
try{bytes=fs.readFileSync(envFile);}catch(e){console.error(`/etc/uptime-goblin.env cannot be read (${e.code||e.name}). ${nothing}`);process.exit(1);}
// The ORBIT_ names from before the rename count as their GOBLIN_ ones, as Uptime Goblin reads them
// (its rule for the names from before the rename); both set to different values is a refusal of
// its start too.
const file=envRead(bytes),text=bytes.toString(),{values:env,conflicts}=envCurrent(file.values);
// Line numbers as an editor counts them, at most five.
const lineList=list=>{const n=[...new Set(list.map(item=>item.line+1))];return `${n.length>1?'lines':'line'} ${n.slice(0,5).join(', ')}${n.length>5?', …':''}`;};
const kind=(list,...states)=>list.filter(item=>states.includes(item.state??item.why));
if(file.refused.length){
  const nul=kind(file.refused,'nul'),utf8=kind(file.refused,'utf8');
  console.error(`systemd would not read /etc/uptime-goblin.env, and so would not start Uptime Goblin: the file holds ${[nul.length&&`a NUL character (${lineList(nul)})`,utf8.length&&`a name or a value that is not valid UTF-8 (${lineList(utf8)})`].filter(Boolean).join(' and ')}. Correct it (sudoedit /etc/uptime-goblin.env), then run this installer again. ${nothing}`);
  process.exit(1);
}
if(file.joined.length){
  const quote=kind(file.joined,'single','double','doubleEscape'),slash=kind(file.joined,'valueEscape'),comment=kind(file.joined,'commentEscape');
  const where=[quote.length&&`a quote still open at the end of ${lineList(quote)}`,slash.length&&`a backslash at the end of ${lineList(slash)}`,comment.length&&`a comment that ends in a backslash on ${lineList(comment)}, which systemd before version 254 continues`].filter(Boolean);
  console.error(`/etc/uptime-goblin.env continues a setting or a comment onto the next line: ${where.join('; ')}. This installer rewrites the file line by line, and node --env-file, with which it checks that Uptime Goblin serves after it starts it, reads such lines otherwise than systemd. Put each setting on a line of its own (sudoedit /etc/uptime-goblin.env): close each quote on the line that opens it, and end no line, a comment included, with a backslash. Then run this installer again. ${nothing}`);
  process.exit(1);
}
const problems=conflicts.length?[envConflicts(conflicts)+'.']:[],differ=[];
try{
  const {displaySessionLimits,legacyBasicSetting,listenHost,listenPort,quoted}=require(path.join(source,'lib/environment.mjs'));
  const {parseAllowUnlimited,supervisedSetting}=require(path.join(source,'lib/resource-limits.mjs'));
  const {connectionsPerClient,trustedProxies}=require(path.join(source,'lib/throttle.mjs'));
  const displayDays=key=>value=>displaySessionLimits({[key]:value});
  for(const [check,value] of [[listenHost,env.HOST],[listenPort,env.PORT],[legacyBasicSetting,env.GOBLIN_LEGACY_BASIC],[parseAllowUnlimited,env.GOBLIN_ALLOW_UNLIMITED],[supervisedSetting,env.GOBLIN_SUPERVISED],[connectionsPerClient,env.GOBLIN_MAX_CONNECTIONS_PER_CLIENT],...(trustOption?[]:[[trustedProxies,env.GOBLIN_TRUST_PROXY]]),[displayDays('GOBLIN_DISPLAY_SESSION_DAYS'),env.GOBLIN_DISPLAY_SESSION_DAYS],[displayDays('GOBLIN_DISPLAY_IDLE_DAYS'),env.GOBLIN_DISPLAY_IDLE_DAYS]]){
    try{check(value);}catch(e){if(!e.refusal)throw e;problems.push(e.message);}
  }
  const verifier=parseEnv(text),shown=value=>value===undefined?'unset':quoted(value,80);
  const effective=(check,value)=>{try{return String(check(value));}catch(e){if(!e.refusal)throw e;return null;}};
  for(const [key,check] of [['HOST',listenHost],['PORT',listenPort]])
    if(effective(check,env[key])!==effective(check,verifier[key]))differ.push(`${key} is ${shown(env[key])} for systemd and ${shown(verifier[key])} for node --env-file`);
}catch(e){console.error(`HOST and PORT in /etc/uptime-goblin.env could not be checked (${e.code||e.name}). ${nothing}`);process.exit(1);}
if(problems.length){console.error(`This release of Uptime Goblin would refuse to start with /etc/uptime-goblin.env (exit status 78): ${problems.join(' ')} Correct ${problems.length>1?'them':'it'} in /etc/uptime-goblin.env (sudoedit /etc/uptime-goblin.env), then run this installer again. ${nothing}`);process.exit(1);}
if(differ.length){console.error(`systemd, which starts Uptime Goblin, and node --env-file, with which this installer checks that Uptime Goblin serves after it starts it (and after a rollback), read /etc/uptime-goblin.env differently: ${differ.join('; ')}. Correct the file (sudoedit /etc/uptime-goblin.env): end each line with a line feed (a carriage return alone ends a line for systemd, not for Node), write no export before a name, and write HOST and PORT without quotes or backslashes. Then run this installer again. ${nothing}`);process.exit(1);}
NODE
  } | "$goblin_node" - "$goblin_cur_env" "$goblin_source" "$goblin_trust_proxy" || exit 1
fi
# HOST and PORT as systemd gives them to Uptime Goblin, which is not always what /etc/uptime-goblin.env says. The
# unit reads that file, and a drop-in can add an EnvironmentFile= read after it, set a name the
# file does not set (Environment=, PassEnvironment=, or systemd's own environment: systemctl
# show-environment) or remove one (UnsetEnvironment=). The healthcheck reads the file alone, so
# with such a drop-in its check after the start probed another port than Uptime Goblin's: a working
# upgrade was rolled back, and the restored release "could not be verified". Here both are worked
# out as systemd does for the unit this installer writes (deploy/uptime-goblin.service) with the drop-ins
# systemd has loaded for uptime-goblin.service (its DropInPaths), and the install is refused, changing
# nothing, where either differs from /etc/uptime-goblin.env (by this release's rules, as above) or cannot
# be told here: a specifier (%i, …) or a file pattern (*, ?, [) that this installer does not
# expand, a PassEnvironment= that would decide it (systemd's own process environment is not read
# here), or what this installer cannot read (systemctl show or show-environment failing, a
# drop-in, a file a drop-in names, with a leading "-" or without, that is not a regular file or is
# larger than 1 MiB). A file that a drop-in's EnvironmentFile= names without a leading "-" and
# that systemd could not read (missing, or holding a NUL or text that is not UTF-8) would stop
# Uptime Goblin from starting at all: refused too. Where systemd has not loaded uptime-goblin.service (LoadState
# other than loaded, as on a first install, where it is not-found) it lists no drop-in for it, but
# once this installer has written the unit and run daemon-reload the drop-ins on disk count:
# those in the drop-in directories (uptime-goblin.service.d, then service.d) of its search path for system
# units (as systemd-analyze unit-paths lists it on Debian 13, and /lib/systemd/system), as systemd
# lists them (see onDisk() below), are read instead. (A first install read none, so with a drop-in
# that set PORT, Uptime Goblin served on that port, the check after the start probed the file's, and the
# install failed with nothing to restore.) While systemd reports NeedDaemonReload=yes for a loaded
# uptime-goblin.service, the drop-ins it lists are those it read last, and the daemon-reload below makes
# those on disk count: unless those on disk are exactly the files it lists, the install is
# refused, asking for a daemon-reload first.
#
# The unit and its drop-ins are read by an emulation of part of systemd's config_parse()
# (src/shared/conf-parser.c), compared with systemd 257 (Debian 13) on chosen inputs; it is not a
# copy of systemd's parser, and may read other inputs otherwise. It emulates this: a line ends at
# LF, CR or CRLF; one whose first character after blanks is # or ; is a comment, also inside a
# continued line; a UTF-8 byte order mark at the very start of the file is dropped after that test,
# so a first line starting with one is never a comment; a line ending in a backslash that escapes
# nothing goes on with the next line (the backslash becomes a space) up to an empty line or the
# end; a line other than a comment that is not UTF-8, or a section header without its ], ends the
# file there; only [Service] counts, and keys match exactly. A value is split into words as
# extract_first_word() does with EXTRACT_UNQUOTE and EXTRACT_CUNESCAPE: quotes around any part of a
# word, C escapes in and outside them, and an error (a quote left open, an escape it does not know)
# drops the rest of that line's words; a word that is not a valid assignment (or name) is ignored,
# and an empty value clears the list. The order is exec_invoke()'s: systemd's own environment, then
# PassEnvironment=, then Environment=, then each EnvironmentFile= in turn (the last that sets a
# name counts), then UnsetEnvironment= (a name, or NAME=value for that value only).
# It refuses ("could not be checked", changing nothing) a drop-in that holds any of six forms. In
# each, systemd 257 reads some inputs otherwise than this emulation, and with some of those it
# gave Uptime Goblin another PORT than this emulation found; the form is refused as a whole, also where
# the two read it alike. The forms: a NUL (systemd ends the line there); a UTF-8 byte order mark
# other than at the very start (systemd drops the first one it finds at the start of any line); a
# line feed followed by a carriage return after a line that a backslash continues (one line end
# for systemd, so that text after the carriage return goes on with the continued line); a section
# header with a quote, a backslash or a control character in it (systemd stops reading the file
# there); an EnvironmentFile= path that is not in normal form or is longer than systemd takes
# (systemd ignores a value of 4096 bytes or more, its leading - included, once %% is %; it reads
# /etc//x, /etc/./x, /../etc/x, /etc/x/ and /etc/x/. as /etc/x, as the kernel does for the first
# three only, and then ignores a path with a .. component or a component over 255 bytes); and a
# PassEnvironment= value with a backslash (systemd takes the next character as it is there, with
# no C escapes). It does not emulate the rest of systemd's parser, and in particular not a setting
# whose own parser rejects its value so that systemd stops reading the rest of that drop-in
# (ExecStartPre=./x does under systemd 257): the settings after such a line are read here.
#
# On a first install /etc/uptime-goblin.env is the one written below (HOST from --listen, PORT=4317, and
# a random GOBLIN_PASSWORD).
#
# Then the admin password, which Uptime Goblin refuses every start without (exit status 78). auth.json in
# the data directory is read with this release's own reader (readAuthRecord), the one Uptime Goblin's
# start reads it with, but as root: one that it refuses (a symbolic link, not a regular file, over
# 8192 bytes or not a valid password record) stops here whatever GOBLIN_PASSWORD is, since Uptime Goblin
# ignores GOBLIN_PASSWORD while auth.json is there, and one that even root cannot open or read (an
# error other than its absence or that of the data directory) stops as "could not be checked".
# Root reads a file that the uptime-goblin account, which Uptime Goblin runs as, may not be able to read: that
# account's own check comes later, once the data directory is that account's (after the key
# files' check). Unless the data directory holds a valid auth.json, GOBLIN_PASSWORD as systemd
# gives it, worked out the same way, must be set, not empty, and one that this release's own
# check (checkBootstrapPassword) accepts. Without one an upgrade would stop Uptime Goblin, fail to start
# it and roll back (1.4.x refuses the same GOBLIN_PASSWORD values, so the rollback would leave
# Uptime Goblin down too), and an install over an existing /etc/uptime-goblin.env or data directory would leave
# Uptime Goblin down with nothing to restore: refused here instead, changing nothing, with what Uptime Goblin's
# own refusal says to do. Neither the password nor what auth.json holds is ever printed.
#
# Then, worked out the same way, the settings the step before this one checked in /etc/uptime-goblin.env
# alone (GOBLIN_LEGACY_BASIC, GOBLIN_ALLOW_UNLIMITED, GOBLIN_SUPERVISED,
# GOBLIN_MAX_CONNECTIONS_PER_CLIENT and GOBLIN_TRUST_PROXY, the last with --trust-proxy applied as
# the step that rewrites /etc/uptime-goblin.env below will apply it), by the same rules: a drop-in or
# systemd's own environment can set them too, and one this release refuses would stop the upgrade
# the same way. Where systemd would decide one in a way the installer cannot read (a specifier, a
# file pattern, PassEnvironment=, systemctl show-environment failing) the install stops too, "could
# not be checked", changing nothing. GOBLIN_INSECURE_HTTP_SESSIONS is worked out the same way, and
# printed with GOBLIN_TRUST_PROXY for the plain-HTTP step, the proxy preflight and the step that
# rewrites /etc/uptime-goblin.env below, as JSON ({trustProxy, insecure, insecureFrom}: the value, ''
# when systemd gives none; true or false where Uptime Goblin reads a yes or no, null otherwise; where
# systemd takes GOBLIN_INSECURE_HTTP_SESSIONS from, null for /etc/uptime-goblin.env itself or nowhere).
# A function, so that its output is kept (bash 3.2 reads a here-document inside $(…) for quotes).
goblin_systemd_env() {
{
  printf '%s\n' "$goblin_env_js"
  cat <<'NODE'
const fs=require('node:fs'),path=require('node:path'),{parseEnv}=require('node:util'),{spawnSync}=require('node:child_process');
const [envFile,source,root,listen,dataDir,trustOption]=process.argv.slice(2);
const nothing='Nothing was changed.';
const {listenHost,listenPort,quoted}=require(path.join(source,'lib/environment.mjs'));
const fix='Set HOST and PORT in /etc/uptime-goblin.env alone (sudoedit /etc/uptime-goblin.env): no drop-in (sudo systemctl edit uptime-goblin), file that one names, or systemd environment (sudo systemctl unset-environment HOST PORT) should set, pass or remove them. Then run this installer again.';
const stop=why=>{console.error(`HOST and PORT as systemd would give them to Uptime Goblin could not be checked: ${why}. This installer checks that Uptime Goblin serves, after it starts it (and after a rollback), at the HOST and PORT in /etc/uptime-goblin.env alone. ${fix} ${nothing}`);process.exit(1);};
const wontStart=why=>{console.error(`systemd would not start Uptime Goblin: ${why}. Correct the drop-in (sudo systemctl edit uptime-goblin) or the file, then run this installer again. ${nothing}`);process.exit(1);};
// Unit files and environment files are read as bytes (one character each, latin1), as systemd reads them.
const text=bytes=>Buffer.from(bytes,'latin1').toString();
// As written when it is printable ASCII without blanks, quotes or backslashes; quoted otherwise.
const named=file=>/^[\x21\x23-\x26\x28-\x5b\x5d-\x7e]+$/.test(file)?file:quoted(text(file),200);
const shown=value=>value===undefined?'unset':quoted(value,80);
// A file of this host as root reads it here: never waiting on a FIFO, a regular file only, at most 1 MiB.
const readHost=file=>{
  const fd=fs.openSync(Buffer.concat([Buffer.from(root),Buffer.from(file,'latin1')]),fs.constants.O_RDONLY|fs.constants.O_NONBLOCK);
  try{
    if(!fs.fstatSync(fd).isFile())throw Object.assign(new Error(),{code:'not a regular file'});
    const buffer=Buffer.alloc(2**20+1);let got=0;
    for(let n;got<buffer.length&&(n=fs.readSync(fd,buffer,got,buffer.length-got,null))>0;)got+=n;
    if(got>2**20)throw Object.assign(new Error(),{code:'larger than 1 MiB'});
    return buffer.subarray(0,got);
  }finally{fs.closeSync(fd);}
};
// /etc/uptime-goblin.env: the file, or on a first install the one written below (its GOBLIN_PASSWORD
// stands for the random one written there: 32 characters, which Uptime Goblin accepts).
let own;try{own=fs.readFileSync(envFile);}catch(e){if(e.code!=='ENOENT')throw e;own=Buffer.from(`HOST=${listen}\nPORT=4317\nGOBLIN_PASSWORD=${'r'.repeat(32)}\n`);}
const verifier=parseEnv(own.toString());
// The six forms of a drop-in that this installer refuses, since it cannot verify that it reads
// them as systemd does (see the comment above).
const forms={
  nul:'a NUL character',
  bom:'a UTF-8 byte order mark other than at its very start',
  lfcr:'a line feed followed by a carriage return after a line that a backslash continues',
  header:'a section header with a quote, a backslash or a control character in it',
  path:'an EnvironmentFile= path that is not in normal form (a . or .. component, two slashes in a row or a slash at its end) or is longer than systemd takes (a component of more than 255 bytes, or 4096 bytes or more, a leading - included)',
  pass:'a PassEnvironment= value with a backslash in it',
};
const unverifiable=(file,form)=>{console.error(`HOST and PORT as systemd would give them to Uptime Goblin could not be checked: the drop-in ${named(file)} holds ${forms[form]}, and this installer cannot verify that it reads that form as systemd does. Remove that from the drop-in (sudo systemctl edit uptime-goblin, or edit the file), then run this installer again. ${nothing}`);process.exit(1);};
// [{key, value}] of a unit file's [Service] section, both as bytes. A line other than a comment
// that is not UTF-8, or a section header without its ], ends the file there for systemd: what
// came before it counts. `dropIn`, the drop-in's path, or null for the unit this installer writes:
// a drop-in holding one of the forms above is refused.
const serviceSettings=(bytes,dropIn)=>{
  const s=bytes.toString('latin1'),out=[],strip=t=>t.replace(/^[ \t\n\r]+|[ \t\n\r]+$/g,'');let section=null,joined=null;
  const refuse=form=>{if(dropIn!==null)unverifiable(dropIn,form);};
  if(s.includes('\0'))refuse('nul');
  if(s.indexOf('\xef\xbb\xbf',1)>=0)refuse('bom');
  const take=line=>{
    const l=strip(line);
    if(!l)return true;
    if(l[0]==='['){if(!l.endsWith(']'))return false;section=l.slice(1,-1);if(/["'\\\x01-\x1f\x7f]/.test(section))refuse('header');return true;}
    const at=l.indexOf('=');
    if(section==='Service'&&at>=0)out.push({key:strip(l.slice(0,at)),value:strip(l.slice(at+1))});
    return true;
  };
  // The lines as envLines() splits them, each followed by what ends it.
  const parts=s.split(/(\r\n|\r|\n)/);
  for(let i=0;i<parts.length;i+=2){
    let line=parts[i];
    // A lone LF whose next byte is a CR.
    const lfcr=parts[i+1]==='\n'&&parts[i+2]===''&&parts[i+3]?.[0]==='\r';
    if(i===0&&line.startsWith('\xef\xbb\xbf'))line=line.slice(3);
    else if(/^[ \t\n\r]*[#;]/.test(line)){if(joined!==null&&lfcr)refuse('lfcr');continue;}
    if(!envUtf8(line))return out;
    let escaped=false;for(const c of line)escaped=!escaped&&c==='\\';
    if(escaped){joined=(joined??'')+line.slice(0,-1)+' ';if(lfcr)refuse('lfcr');continue;}
    const whole=(joined??'')+line;joined=null;
    if(!take(whole))return out;
  }
  if(joined!==null)take(joined);
  return out;
};
// One escape after a backslash at s[i], as cunescape_one(): [bytes, length], or null for one it refuses.
const utf8=v=>v<0x80?String.fromCharCode(v):v<0x800?String.fromCharCode(0xc0|v>>6,0x80|v&63):v<0x10000?String.fromCharCode(0xe0|v>>12,0x80|v>>6&63,0x80|v&63):String.fromCharCode(0xf0|v>>18,0x80|v>>12&63,0x80|v>>6&63,0x80|v&63);
const cescape=(s,i)=>{
  const c=s[i]??'',simple={a:'\x07',b:'\b',f:'\f',n:'\n',r:'\r',t:'\t',v:'\v',s:' ','\\':'\\','"':'"',"'":"'"};
  if(Object.hasOwn(simple,c))return [simple[c],1];
  const digits=(n,re)=>{const d=s.slice(i+1,i+1+n);return d.length===n&&re.test(d)?d:null;};
  if(c==='x'){const d=digits(2,/^[0-9a-fA-F]+$/);return d&&parseInt(d,16)?[String.fromCharCode(parseInt(d,16)),3]:null;}
  if(c==='u'||c==='U'){
    const n=c==='u'?4:8,d=digits(n,/^[0-9a-fA-F]+$/),v=d&&parseInt(d,16);
    if(!v||(c==='U'&&(v>=0x110000||(v&0xfffff800)===0xd800||(v>=0xfdd0&&v<=0xfdef)||(v&0xfffe)===0xfffe)))return null;
    return [utf8(v),n+1];
  }
  if(/^[0-7]{3}$/.test(s.slice(i,i+3))){const v=parseInt(s.slice(i,i+3),8);return v&&v<256?[String.fromCharCode(v),3]:null;}
  return null;
};
// The words of a value, as extract_first_word() with EXTRACT_UNQUOTE|EXTRACT_CUNESCAPE takes them,
// up to the first error.
const words=value=>{
  const list=[],blank=c=>c===' '||c==='\t'||c==='\n'||c==='\r';let p=0;
  for(;;){
    while(p<value.length&&blank(value[p]))p++;
    if(p===value.length)return list;
    let word='',quote='';
    for(;p<value.length&&(quote||!blank(value[p]));p++){
      const c=value[p];
      if(c==='\\'){const e=cescape(value,p+1);if(!e)return list;word+=e[0];p+=e[1];}
      else if(quote){if(c===quote)quote='';else word+=c;}
      else if(c==="'"||c==='"')quote=c;
      else word+=c;
    }
    if(quote)return list;
    list.push(word);
  }
};
// Specifiers: %% is %; null for any other, which this installer does not expand.
const printf=word=>{let out='';for(let i=0;i<word.length;i++){if(word[i]!=='%')out+=word[i];else if(word[i+1]==='%')out+=word[++i];else return null;}return out;};
const units=[{file:'/etc/systemd/system/uptime-goblin.service',bytes:fs.readFileSync(path.join(source,'deploy/uptime-goblin.service'))}];
const listed=spawnSync('systemctl',['show','uptime-goblin.service','--property=LoadState,DropInPaths,NeedDaemonReload'],{encoding:'latin1'});
const unit=new Map(listed.error||listed.status!==0?[]:listed.stdout.split('\n').filter(line=>line.includes('=')).map(line=>[line.slice(0,line.indexOf('=')),line.slice(line.indexOf('=')+1)]));
if(!unit.has('LoadState')||!unit.has('DropInPaths')||!unit.has('NeedDaemonReload'))stop(`systemctl show uptime-goblin.service did not list its drop-ins (${listed.error?.code||`exit status ${listed.status}`})`);
// The drop-ins on disk, as systemd finds them for uptime-goblin.service at a daemon-reload
// (unit_file_find_dropin_paths() in src/shared/dropin.c, compared with systemd 257): the
// directories uptime-goblin.service.d, then service.d, each in the order of its search path for system
// units (as systemd-analyze unit-paths lists it on Debian 13, and /lib/systemd/system; a directory
// reached twice, as /lib is through /usr/lib, counts once); in them each name that ends in .conf
// and does not start with a dot (FOREACH_DIRENT() skips hidden ones; systemd lists a directory or
// another node so named too, which is read below as the drop-in it lists would be); of those with
// the same name, the first; in the order of their names, byte by byte. Paths as systemctl show
// lists them, one byte to a character.
const searchPath=['/etc/systemd/system.control','/run/systemd/system.control','/run/systemd/transient','/run/systemd/generator.early','/etc/systemd/system','/etc/systemd/system.attached','/run/systemd/system','/run/systemd/system.attached','/run/systemd/generator','/usr/local/lib/systemd/system','/usr/lib/systemd/system','/lib/systemd/system','/run/systemd/generator.late'];
const onDisk=()=>{
  const dirs=new Set(),byName=new Map();
  for(const sub of ['uptime-goblin.service.d','service.d'])for(const dir of searchPath){
    // On a host with the Orbit layout the migration renames /etc/systemd/system/orbit.service.d to
    // uptime-goblin.service.d (and refuses orbit.service drop-ins elsewhere): read them there.
    const at=layoutOld&&dir==='/etc/systemd/system'&&sub==='uptime-goblin.service.d'?`${dir}/orbit.service.d`:`${dir}/${sub}`;let entries;
    try{const real=fs.realpathSync(root+at);if(dirs.has(real))continue;dirs.add(real);entries=fs.readdirSync(root+at,{encoding:'buffer'});}catch{continue;}
    for(const entry of entries){
      const name=entry.toString('latin1');
      if(name.endsWith('.conf')&&!name.startsWith('.')&&!byName.has(name))byName.set(name,`${at}/${name}`);
    }
  }
  return [...byName.keys()].sort((a,b)=>a<b?-1:a>b?1:0).map(name=>byName.get(name));
};
let dropIns=unit.get('DropInPaths').split(' ').filter(Boolean);
// Where systemd has not loaded uptime-goblin.service (a LoadState other than loaded: not-found on a first
// install), it lists no drop-in for it, also with one on disk; the unit this installer writes,
// and its daemon-reload, make those on disk count: they are read instead.
if(unit.get('LoadState')!=='loaded')dropIns=onDisk();
// While systemd reports NeedDaemonReload=yes, the list is of the drop-ins it read last, and the
// daemon-reload below makes those on disk count. Those on disk must then be exactly the files
// listed.
else if(unit.get('NeedDaemonReload')!=='no'){
  const real=file=>{try{return path.join(fs.realpathSync(path.dirname(file)),path.basename(file));}catch{return file;}};
  const loaded=new Set(dropIns.map(file=>real(root+text(file)))),found=new Set(onDisk().map(file=>real(root+text(file))));
  if(loaded.size!==found.size||[...found].some(file=>!loaded.has(file))){console.error(`systemd has not read the drop-ins of uptime-goblin.service as they are now (NeedDaemonReload=${unit.get('NeedDaemonReload')}): the files in its drop-in directories are not those it read last, which are the ones it lists. So this installer cannot tell which HOST and PORT systemd will give Uptime Goblin after the daemon-reload this installer runs. Run sudo systemctl daemon-reload, then run this installer again. ${nothing}`);process.exit(1);}
}
for(const file of dropIns){
  let bytes;try{bytes=readHost(file);}catch(e){stop(`the drop-in ${named(file)} cannot be read (${e.code||e.name})`);}
  units.push({file,bytes,dropIn:true});
}
// The lists systemd keeps, each item with the place that set it (`from`). An item this installer
// cannot read has `unknown`, why; a word whose name it cannot tell has name null.
let env=[],files=[],unset=[],pass=[];
for(const {file,bytes,dropIn} of units)for(const {key,value} of serviceSettings(bytes,dropIn?file:null)){
  const where=`${key}= in ${named(file)}`;
  if(key==='EnvironmentFile'){
    if(!value){files=[];continue;}
    const from=`EnvironmentFile=${named(value)} in ${named(file)}`,name=printf(value);
    if(name===null){files.push({unknown:`${from} names its file with a specifier, which this installer does not expand`});continue;}
    const optional=name.startsWith('-'),at=optional?name.slice(1):name;
    // A relative path: systemd ignores the line.
    if(!at.startsWith('/'))continue;
    // One that systemd reads as another path, or ignores: unit_path_printf() ignores a value of
    // 4096 bytes or more (`name`: once %% is %, with its "-"), and path_simplify_and_warn() then
    // takes the path.
    if(dropIn&&(/\/\/|\/\.\.?(\/|$)|.\/$/.test(at)||name.length>=4096||at.split('/').some(part=>part.length>255)))unverifiable(file,'path');
    files.push(/[*?[\\]/.test(at)?{unknown:`${from} names its files by a pattern, which this installer does not expand`}:{at,optional,from});
  }else if(key==='Environment'||key==='UnsetEnvironment'||key==='PassEnvironment'){
    if(!value){if(key==='Environment')env=[];else if(key==='UnsetEnvironment')unset=[];else pass=[];continue;}
    // systemd splits PassEnvironment= without C escapes: a backslash takes the next character as it is.
    if(dropIn&&key==='PassEnvironment'&&value.includes('\\'))unverifiable(file,'pass');
    for(const raw of words(value)){
      const word=printf(raw),eq=raw.indexOf('='),rawName=eq<0?raw:raw.slice(0,eq);
      if(word===null){
        const name=rawName.includes('%')?null:rawName;
        if(name===null||envName(name))({Environment:env,UnsetEnvironment:unset,PassEnvironment:pass})[key].push({name,unknown:`${where} ${{Environment:'sets',UnsetEnvironment:'removes',PassEnvironment:'passes'}[key]} ${name===null?'a variable whose name has':`${name} with`} a specifier, which this installer does not expand`});
        continue;
      }
      const at=word.indexOf('='),name=at<0?word:word.slice(0,at),assigned=at<0?undefined:text(word.slice(at+1));
      if(!envName(name)||!envUtf8(word))continue;
      if(key==='Environment'){if(at>=0)env.push({name,value:assigned,from:where});}
      else if(key==='PassEnvironment'){if(at<0)pass.push({name,from:where});}
      else unset.push({name,value:assigned,from:where});
    }
  }
}
// What each environment file sets for systemd; a file without "-" that systemd could not read
// stops Uptime Goblin's start. One that this installer does not read (not a regular file, or larger than
// 1 MiB) cannot be told, with "-" too: systemd may read it.
for(const f of files){
  if(f.unknown)continue;
  let bytes;
  if(f.at==='/etc/uptime-goblin.env')bytes=own;
  else try{bytes=readHost(f.at);}catch(e){
    if(e.code==='not a regular file'||e.code==='larger than 1 MiB')stop(`${f.from} names a file that is ${e.code}, which this installer does not read`);
    if(f.optional){f.values={};continue;}
    wontStart(`${f.from} names a file that cannot be read (${e.code||e.name})`);
  }
  const read=envRead(bytes);
  if(read.refused.length&&!f.optional)wontStart(`${f.from} names a file that holds a NUL character, or a name or value that is not valid UTF-8, which systemd does not read`);
  f.values=read.refused.length?{}:read.values;
}
let manager=null;
// `unknown`: what to do where the value cannot be told (HOST and PORT: stop).
const managerEnv=(unknown=stop)=>{
  if(manager)return manager;
  const r=spawnSync('systemctl',['show-environment'],{encoding:'utf8'});
  if(r.error||r.status!==0)unknown(`systemctl show-environment did not answer (${r.error?.code||`exit status ${r.status}`})`);
  manager=new Map();
  for(const line of r.stdout.split('\n')){const at=line.indexOf('=');if(at>0)manager.set(line.slice(0,at),line.slice(at+1));}
  return manager;
};
const givesOne=(key,unknown=stop)=>{
  let got=null;
  for(const f of files)if(f.unknown||Object.hasOwn(f.values,key))got=f.unknown?f:{value:f.values[key],from:f.from,at:f.at};
  if(!got)for(const e of env)if(e.name===key||e.name===null)got=e;
  if(!got)for(const p of pass)if(p.name===key||p.name===null)got=p.unknown?p:{unknown:`${p.from} passes ${key} from the environment of systemd's own process, which this installer does not read`};
  if(!got&&managerEnv(unknown).has(key))got={value:managerEnv(unknown).get(key),from:"systemd's own environment, as systemctl show-environment shows it"};
  for(const u of unset)if((u.name===key||u.name===null)&&u.unknown)got=u;
  if(got?.unknown)unknown(got.unknown);
  for(const u of unset)if(u.name===key&&got&&(u.value===undefined||u.value===got.value))got={value:undefined,from:u.from};
  return got??{value:undefined,from:'set nowhere that systemd reads for Uptime Goblin'};
};
// A GOBLIN_ setting and its ORBIT_ name from before the rename, as Uptime Goblin reads them
// (its rule for the names from before the rename): the GOBLIN_ one where systemd gives it, else the
// ORBIT_ one. Both given,
// with different values, refuses its start (exit status 78): `conflict` is then the ORBIT_ one.
// Where the ORBIT_ one cannot be told (systemd's own environment unread, say) it counts as unset:
// what stops a check is what the GOBLIN_ one needs, as before the rename.
const gives=(key,unknown=stop)=>{
  const now=givesOne(key,unknown);
  if(!key.startsWith('GOBLIN_'))return now;
  let old;
  try{old=givesOne('ORBIT_'+key.slice(7),why=>{throw Object.assign(new Error(why),{oldName:true});});}
  catch(e){if(!e.oldName)throw e;old={value:undefined,from:'set nowhere that systemd reads for Uptime Goblin'};}
  if(now.value!==undefined&&old.value!==undefined&&now.value!==old.value)return {...now,conflict:old};
  return now.value!==undefined||old.value===undefined?now:old;
};
const conflictText=(key,given)=>`${envConflicts([key])} (systemd would give Uptime Goblin ${key} from ${given.from} and ${'ORBIT_'+key.slice(7)} from ${given.conflict.from}).`;
const differ=[];
try{
  const effective=(check,value)=>{try{return String(check(value));}catch(e){if(!e.refusal)throw e;return null;}};
  for(const [key,check] of [['HOST',listenHost],['PORT',listenPort]]){
    const systemd=gives(key),probed=effective(check,verifier[key]),given=effective(check,systemd.value);
    if(given!==probed)differ.push(`${key} is ${shown(systemd.value)} for systemd (${systemd.from}${given===null?'; this release refuses it':''}) and ${shown(verifier[key])} in /etc/uptime-goblin.env`);
  }
}catch(e){console.error(`HOST and PORT as systemd would give them to Uptime Goblin could not be checked (${e.code||e.name}). ${nothing}`);process.exit(1);}
if(differ.length){console.error(`systemd would give Uptime Goblin another HOST or PORT than /etc/uptime-goblin.env gives, and this installer checks that Uptime Goblin serves, after it starts it (and after a rollback), at the HOST and PORT in /etc/uptime-goblin.env alone: ${differ.join('; ')}. ${fix} ${nothing}`);process.exit(1);}
// The admin password (see the comment above): auth.json in the data directory, read by this
// release's own reader, the one Uptime Goblin's start reads it with, but as root (readAuthRecord: never
// through a symbolic link, never waiting on a FIFO, only a regular file of at most 8192 bytes, read
// no further, that holds a valid password record; it only reads, and changes no mode). One it
// refuses stops the install whatever GOBLIN_PASSWORD is: Uptime Goblin ignores GOBLIN_PASSWORD while
// auth.json is there. Where there is none, a non-empty GOBLIN_PASSWORD for systemd that this
// release's own check accepts. Whether the uptime-goblin account can read it is checked later.
const {checkBootstrapPassword,readAuthRecord}=require(path.join(source,'lib/identity/password.mjs'));
const passwordFix='Set GOBLIN_PASSWORD (12 to 1024 characters) in /etc/uptime-goblin.env (sudoedit /etc/uptime-goblin.env), and let no drop-in (sudo systemctl edit uptime-goblin) empty or remove it, then run this installer again. If Uptime Goblin had a password before, restore /var/lib/uptime-goblin/auth.json from a backup instead, or set GOBLIN_PASSWORD: it becomes the admin password and signs out every session.';
const passwordUnknown=why=>{console.error(`Whether Uptime Goblin would have an admin password could not be checked: ${why}. Uptime Goblin refuses to start without one (exit status 78). ${passwordFix} ${nothing}`);process.exit(1);};
let authJson=false;
try{authJson=readAuthRecord(dataDir)!==null;}catch(e){
  if(e.refusal){console.error(`This release of Uptime Goblin would refuse to start (exit status 78) with "${e.message}": /var/lib/uptime-goblin/auth.json is a symbolic link, not a regular file, larger than 8192 bytes or not a valid password record, and while it is there Uptime Goblin ignores GOBLIN_PASSWORD. Restore /var/lib/uptime-goblin/auth.json from a backup, or move it out of /var/lib/uptime-goblin and set GOBLIN_PASSWORD (12 to 1024 characters) in /etc/uptime-goblin.env (sudoedit /etc/uptime-goblin.env): it becomes the admin password and signs out every session. Then run this installer again. ${nothing}`);process.exit(1);}
  if(e.code!=='ENOTDIR')passwordUnknown(`/var/lib/uptime-goblin/auth.json cannot be checked (${e.code||e.name})`);
}
if(!authJson){
  const given=gives('GOBLIN_PASSWORD',passwordUnknown);
  if(given.conflict){console.error(`This release of Uptime Goblin would refuse to start (exit status 78): ${conflictText('GOBLIN_PASSWORD',given)} ${nothing}`);process.exit(1);}
  if(!given.value){
    const nowhere='set nowhere that systemd reads for Uptime Goblin';
    console.error(`This release of Uptime Goblin would refuse to start (exit status 78): Uptime Goblin needs an admin password, and none is set: /var/lib/uptime-goblin has no auth.json, and GOBLIN_PASSWORD ${given.from===nowhere?`is ${nowhere}`:`is ${given.value===undefined?'removed':'empty'} for Uptime Goblin (${given.from})`}. ${passwordFix} ${nothing}`);
    process.exit(1);
  }
  // One that this release's own check refuses (too short, only spaces, too long, not well-formed).
  try{checkBootstrapPassword(given.value);}catch(e){
    if(!e.refusal)passwordUnknown(`this release could not check GOBLIN_PASSWORD (${e.code||e.name})`);
    console.error(`This release of Uptime Goblin would refuse to start (exit status 78) with "${e.message}": /var/lib/uptime-goblin has no auth.json, and the GOBLIN_PASSWORD that systemd would give Uptime Goblin (${given.from}) is not one Uptime Goblin accepts. ${passwordFix} ${nothing}`);
    process.exit(1);
  }
}
// --trust-proxy: the step that rewrites /etc/uptime-goblin.env below sets its last GOBLIN_TRUST_PROXY line
// to the option (empty for off, 0, false or no), or adds the line where there is none and the
// option names a proxy; systemd reads that from the file then.
if(trustOption){
  const value=proxyOn(trustOption,source)?trustOption:'';
  // The line it rewrites is the GOBLIN_ one, the ORBIT_ one or both, as the file has them; an added
  // line takes the names of the layout it is added to (ORBIT_ in the Orbit layout's file).
  for(const f of files)if(!f.unknown&&f.at==='/etc/uptime-goblin.env'){
    const names=['GOBLIN_TRUST_PROXY','ORBIT_TRUST_PROXY'].filter(name=>Object.hasOwn(f.values,name));
    if(!names.length&&value!=='')names.push(process.env.goblin_env_prefix+'TRUST_PROXY');
    for(const name of names)f.values={...f.values,[name]:value};
  }
}
const valueUnknown=key=>why=>{console.error(`${key} as systemd would give it to Uptime Goblin could not be checked: ${why}. This installer judges it by this release's own rules before anything changes. Set ${key} in /etc/uptime-goblin.env alone, if anywhere (sudoedit /etc/uptime-goblin.env): no drop-in (sudo systemctl edit uptime-goblin), file that one names, or systemd environment (sudo systemctl unset-environment ${key}) should set, pass or remove it. Then run this installer again. ${nothing}`);process.exit(1);};
let decided;
try{
  const {displaySessionLimits,flagValue,legacyBasicSetting}=require(path.join(source,'lib/environment.mjs'));
  const {parseAllowUnlimited,supervisedSetting}=require(path.join(source,'lib/resource-limits.mjs'));
  const {connectionsPerClient,trustedProxies}=require(path.join(source,'lib/throttle.mjs'));
  const problems=[],values={},sources={};
  const displayDays=key=>value=>displaySessionLimits({[key]:value});
  for(const [key,check] of [['GOBLIN_LEGACY_BASIC',legacyBasicSetting],['GOBLIN_ALLOW_UNLIMITED',parseAllowUnlimited],['GOBLIN_SUPERVISED',supervisedSetting],['GOBLIN_MAX_CONNECTIONS_PER_CLIENT',connectionsPerClient],['GOBLIN_TRUST_PROXY',trustedProxies],['GOBLIN_DISPLAY_SESSION_DAYS',displayDays('GOBLIN_DISPLAY_SESSION_DAYS')],['GOBLIN_DISPLAY_IDLE_DAYS',displayDays('GOBLIN_DISPLAY_IDLE_DAYS')],['GOBLIN_INSECURE_HTTP_SESSIONS',null]]){
    const given=gives(key,valueUnknown(key));
    values[key]=given.value;sources[key]=given.at==='/etc/uptime-goblin.env'||given.value===undefined?null:given.from;
    if(given.conflict){problems.push(conflictText(key,given));continue;}
    if(check)try{check(given.value);}catch(e){if(!e.refusal)throw e;problems.push(`${e.message} systemd would give it to Uptime Goblin from ${given.from}.`);}
  }
  if(problems.length){console.error(`This release of Uptime Goblin would refuse to start with the settings systemd would give it (exit status 78): ${problems.join(' ')} Correct ${problems.length>1?'them':'it'} there (a drop-in: sudo systemctl edit uptime-goblin; systemd's own environment: sudo systemctl unset-environment), or set ${problems.length>1?'them':'it'} in /etc/uptime-goblin.env alone (sudoedit /etc/uptime-goblin.env), then run this installer again. ${nothing}`);process.exit(1);}
  const insecure=flagValue(values.GOBLIN_INSECURE_HTTP_SESSIONS);
  decided={trustProxy:values.GOBLIN_TRUST_PROXY??'',insecure:typeof insecure==='boolean'?insecure:null,insecureFrom:sources.GOBLIN_INSECURE_HTTP_SESSIONS};
}catch(e){console.error(`The settings systemd would give Uptime Goblin could not be checked (${e.code||e.name}). ${nothing}`);process.exit(1);}
process.stdout.write(JSON.stringify(decided));
NODE
} | "$goblin_node" - "$goblin_cur_env" "$goblin_source" "$goblin_root" "$goblin_host" "$goblin_cur_data" "$goblin_trust_proxy"
}
goblin_given=$(goblin_systemd_env) || exit 1
# Plain HTTP (sessions spec §3.12, D8). An install that listens on the network (HOST not a
# loopback address) with no proxy it trusts (GOBLIN_TRUST_PROXY as systemd would give it to Uptime Goblin,
# with --trust-proxy applied: worked out in the step above) signs browsers and Basic scripts in
# over plain HTTP, where the network sees every password: Uptime Goblin 1.5 allows that only with
# GOBLIN_INSECURE_HTTP_SESSIONS=1, and this installer never adds that line by itself (it once did,
# so an upgrade turned plain-HTTP sign-in on without anyone choosing it). Unless systemd would
# already give Uptime Goblin a decision (a GOBLIN_INSECURE_HTTP_SESSIONS that Uptime Goblin reads as yes or no,
# worked out in the step above) or --allow-insecure-http chooses it, such an install stops here,
# changing nothing, and says how to put Uptime Goblin behind an HTTPS proxy or how to choose plain HTTP. A
# new install judges --listen and --trust-proxy. HOST is the one in /etc/uptime-goblin.env, which the step
# above found to be the one systemd gives Uptime Goblin.
#
# The =1 that an earlier 1.5 pre-release installer added by itself, under its own comment
# (envPreReleaseOptIn() above, found in /etc/uptime-goblin.env by its lines), decides nothing: without
# --allow-insecure-http, every install whose /etc/uptime-goblin.env holds it stops here first, changing
# nothing, also one on loopback or behind a trusted proxy (a client that reaches an Uptime Goblin on the
# network directly, or a proxy on this host that relays plain HTTP to its loopback address, would
# still sign in over plain HTTP under it), and the proxy preflight of the upgrade from 1.4.x below
# is never reached with it. The message names the line and the three ways to decide.
{
  printf '%s\n' "$goblin_env_js"
  cat <<'NODE'
const fs=require('node:fs');
const [envFile,listen,given,allowInsecure,source]=process.argv.slice(2);
const {trustProxy,insecure}=JSON.parse(given);
let bytes=null;try{bytes=fs.readFileSync(envFile);}catch(e){if(e.code!=='ENOENT')throw e;}
const host=(bytes===null?listen:envValues(bytes).HOST)||'127.0.0.1';
const loopback=host==='localhost'||host==='::1'||/^127(\.[0-9]{1,3}){3}$/.test(host);
const preRelease=bytes===null?-1:envPreReleaseOptIn(envLines(bytes.toString()));
if(preRelease>=0&&allowInsecure!=='1'){
  console.error(`/etc/uptime-goblin.env sets GOBLIN_INSECURE_HTTP_SESSIONS=1 on line ${preRelease+2} under the comment that an earlier Orbit 1.5 pre-release installer wrote with it on line ${preRelease+1} ("# Added by the Orbit 1.5 installer: keeps plain-HTTP sign-in working as in 1.4.x. …"): that installer allowed sign-in over plain HTTP by itself, so this one does not take the line for your choice, and stops until you decide. To refuse sign-in over plain HTTP, set line ${preRelease+2} to GOBLIN_INSECURE_HTTP_SESSIONS=0 (sudoedit /etc/uptime-goblin.env): browsers and scripts then sign in only over HTTPS, through a reverse proxy that GOBLIN_TRUST_PROXY names (it must send X-Forwarded-Proto; nginx: proxy_set_header X-Forwarded-Proto $scheme;), or from the Uptime Goblin computer itself. To keep it, on a network you trust (the password and the sign-in cookie then cross it unencrypted), remove the comment on line ${preRelease+1} or put a comment of your own in its place (sudoedit /etc/uptime-goblin.env), or run this installer again with --allow-insecure-http, which replaces that comment with one that names who chose it. Nothing was changed.`);
  process.exit(1);
}
if(loopback||proxyOn(trustProxy,source)||(preRelease<0&&typeof insecure==='boolean')||allowInsecure==='1')process.exit(0);
const proxy=bytes===null?'run this installer again without --listen (Uptime Goblin then listens on 127.0.0.1) and with --trust-proxy loopback for a proxy on this host, or with --trust-proxy <proxy address> for one on another host':'set HOST=127.0.0.1 in /etc/uptime-goblin.env (sudoedit /etc/uptime-goblin.env) and run this installer again with --trust-proxy loopback for a proxy on this host, or run it again with --trust-proxy <proxy address> for one on another host';
const refuse=bytes===null?'':' To keep sign-in over plain HTTP refused instead, add GOBLIN_INSECURE_HTTP_SESSIONS=0 to /etc/uptime-goblin.env.';
console.error(`Uptime Goblin would listen on ${host} (${bytes===null?'--listen':'HOST in /etc/uptime-goblin.env'}) with no reverse proxy it trusts (GOBLIN_TRUST_PROXY), so browsers and scripts would sign in over plain HTTP, and the network would see each password and sign-in cookie. Uptime Goblin 1.5 allows that only when you choose it. Either serve Uptime Goblin over HTTPS through a reverse proxy: ${proxy}, and make the proxy send X-Forwarded-Proto (nginx: proxy_set_header X-Forwarded-Proto $scheme;). Or, on a network you trust, run this installer again with --allow-insecure-http, which adds GOBLIN_INSECURE_HTTP_SESSIONS=1 to /etc/uptime-goblin.env: passwords then cross the network in clear.${refuse} Nothing was changed.`);
process.exit(1);
NODE
} | "$goblin_node" - "$goblin_cur_env" "$goblin_host" "$goblin_given" "$goblin_allow_insecure_http" "$goblin_source" || exit 1
# Proxy preflight (sessions spec §3.12). Uptime Goblin 1.5 signs browsers in with a cookie, and behind a
# reverse proxy it knows the browser uses HTTPS only from X-Forwarded-Proto. 1.4.3 records in
# run/status.json what its trusted proxy sent; the upgrade from 1.4.x behind a proxy is refused,
# changing nothing, until that record says https. The record starts empty at every start of
# 1.4.3 and is removed when it stops, and 1.4.2 and earlier keep none at all, so each case gets
# its own way forward. Later upgrades skip it: signing in already proves the proxy. The effective
# settings are GOBLIN_TRUST_PROXY and GOBLIN_INSECURE_HTTP_SESSIONS as systemd would give them to
# Uptime Goblin (worked out above, --trust-proxy applied), with --allow-insecure-http applied (the option
# allows plain HTTP where systemd would give Uptime Goblin no yes or no for GOBLIN_INSECURE_HTTP_SESSIONS).
# An /etc/uptime-goblin.env that holds the =1 an earlier 1.5 pre-release installer added by itself
# (envPreReleaseOptIn()) never gets here without the option: the plain-HTTP step stopped it.
if [[ -z $goblin_proxy_proto_checked && -n $goblin_installed_version ]] &&
  goblin_before_15 "$goblin_installed_version" && ! goblin_before_15 "$goblin_new_version"; then
  {
    printf '%s\n' "$goblin_env_js"
    cat <<'NODE'
const fs=require('node:fs');
const [given,statusFile,installed,source,allowInsecure]=process.argv.slice(2);
const systemd=JSON.parse(given);
const trust=String(systemd.trustProxy).trim();
const insecure=systemd.insecure??(allowInsecure==='1'||null);
// --trust-proxy off (or 0, false, no) and such a line name no proxy: nothing to check.
if(!proxyOn(trust,source)||insecure===true)process.exit(0);
// run/status.json is the uptime-goblin account's, like all of /var/lib/uptime-goblin: root reads it only as a
// regular file, never through a link (run/ itself included: the file is opened through run/'s
// own descriptor) or from a FIFO (which would hold the installer), and at most 64 KiB of it.
// Anything else is no record.
const readStatus=file=>{const path=require('node:path'),dir=fs.openSync(path.dirname(file),fs.constants.O_RDONLY|fs.constants.O_DIRECTORY|fs.constants.O_NOFOLLOW);let fd;try{const own=`/proc/self/fd/${dir}`;fd=fs.openSync(path.join(fs.existsSync(own)?own:path.dirname(file),path.basename(file)),fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);}finally{fs.closeSync(dir);}try{if(!fs.fstatSync(fd).isFile())return null;const buffer=Buffer.alloc(65536);let got=0;for(let n;got<buffer.length&&(n=fs.readSync(fd,buffer,got,buffer.length-got,null))>0;)got+=n;return buffer.subarray(0,got).toString('utf8');}finally{fs.closeSync(fd);}};
let status=null;try{status=JSON.parse(readStatus(statusFile)??'null');}catch{}
const ours=status&&typeof status==='object'&&status.version===installed;
const seen=ours?status.observed?.forwardedProto:null;
if(seen==='https')process.exit(0);
const head='Uptime Goblin 1.5 signs browsers in with a cookie and must know whether the browser uses HTTPS.',tail=`On a network you trust you can instead allow sign-in over plain HTTP (the password and the sign-in cookie then cross it unencrypted): run this installer again with --allow-insecure-http, which adds GOBLIN_INSECURE_HTTP_SESSIONS=1 to /etc/uptime-goblin.env where neither that file nor anything else systemd would give Uptime Goblin says yes or no, or set GOBLIN_INSECURE_HTTP_SESSIONS=1 there yourself. If you have checked the proxy yourself, run again with --proxy-proto-checked. Nothing was changed.`;
// 1.4.2 and earlier write no run/status.json: browsing and running again can never pass.
const m=/^(\d+)\.(\d+)\.(\d+)/.exec(installed),recorder=!!m&&(+m[1]>1||(+m[1]===1&&(+m[2]>4||(+m[2]===4&&+m[3]>=3))));
if(!recorder){console.error(`${head} The running Orbit ${installed} does not record what your reverse proxy sends; only 1.4.3 and later do (GOBLIN_TRUST_PROXY=${trust}). Before upgrading: upgrade to 1.4.3 first, open Orbit through nginx once, then run this installer again; or make sure Orbit's nginx location has proxy_set_header X-Forwarded-Proto $scheme; and run this installer again with --proxy-proto-checked. ${tail}`);process.exit(1);}
// 1.4.3 records only while it runs: it removes the record when it stops (an operator's stop
// before upgrading, or a backup that stops it) and a crash leaves one that no longer changes, so
// browsing through nginx cannot help a stopped service until it runs again. Asked only here, on
// the way to a refusal.
if(require('node:child_process').spawnSync('systemctl',['is-active','--quiet',process.env.goblin_service]).status!==0){console.error(`${head} Orbit ${installed} is not running, and it clears its record of what your reverse proxy sends when it stops (GOBLIN_TRUST_PROXY=${trust}). Before upgrading: start it (sudo systemctl start uptime-goblin), open Orbit through nginx once, then run this installer again without stopping Orbit. ${tail}`);process.exit(1);}
console.error(`${head} The running Orbit ${installed} has ${seen==='http'?'recorded X-Forwarded-Proto: http':'not recorded what your reverse proxy sends'} (GOBLIN_TRUST_PROXY=${trust}). Before upgrading: add proxy_set_header X-Forwarded-Proto $scheme; to Orbit's nginx location, reload nginx, open Orbit through nginx once, then run this installer again.${seen==='http'?'':` Orbit ${installed} forgets what it saw each time it starts (a reboot, or a backup that stops and starts it): open Orbit through nginx after its last start.`} ${tail}`);
process.exit(1);
NODE
  } | "$goblin_node" - "$goblin_given" "$goblin_cur_data/run/status.json" "$goblin_installed_version" "$goblin_source" "$goblin_allow_insecure_http" || exit 1
fi
# The encryption key (delivery spec §4.5). Uptime Goblin 1.5 opens its keyring at every start and
# creates it at the first one; the key must stay apart from /var/lib/uptime-goblin, so the installer
# provisions /etc/uptime-goblin/secret.key and names it in /etc/uptime-goblin.env. It picks the key in the order
# Uptime Goblin itself does (lib/keyring.mjs resolveKey), and when the data already has a keyring it
# proves the key it picks opens it, with this release's own code, on a private copy of
# control.sqlite (the live files are never opened: as root that could leave a root-owned -shm).
# Everything here only reads: a refusal changes nothing on the host. The plan is applied once
# the uptime-goblin account exists (the key files Uptime Goblin opens are tried as that account) and in the step
# that edits /etc/uptime-goblin.env, below.
goblin_key_dir=$(mktemp -d /tmp/uptime-goblin-key.XXXXXX)
trap 'rm -rf -- "$goblin_key_dir"' EXIT
systemctl cat "$goblin_service" >"$goblin_key_dir/unit.txt" 2>/dev/null || true
{
  printf '%s\n' "$goblin_env_js"
  cat <<'NODE'
const fs=require('node:fs'),path=require('node:path');
const [envFile,root,dataDir,unitFile,source,planFile]=process.argv.slice(2);
const {parseKey,keyFingerprint}=require(path.join(source,'lib/keyring.mjs'));
const {inspectKeyring}=require(path.join(source,'lib/db/control.mjs'));
const nothing='Nothing was changed.';
const refuse=text=>{console.error(text);process.exit(1);};
// The unit as systemd shows it (systemctl cat, its drop-ins included), saved in the installer's
// private directory. A SetCredential= line in it is the key itself, so it is read once, here,
// and removed before the private copy of the data is made in that directory (step 0 below):
// the key and a copy of the data it opens are never there together, even when a run is killed.
// systemd ends a line of a unit file at LF, CR or CRLF too. Split on LF alone, a drop-in with
// CRLF line ends hid its LoadCredential= line: for data without a keyring the installer then
// generated a key, whose GOBLIN_SECRET_KEY_FILE line Uptime Goblin takes before the credential.
const unitText=envLines((()=>{try{return fs.readFileSync(unitFile,'utf8');}finally{fs.rmSync(unitFile,{force:true});}})());
// Paths as Uptime Goblin sees them; this host's files are under `root` (tests install into a scratch root).
const onHost=file=>root+(path.isAbsolute(file)?file:path.join(layoutPath('/opt/uptime-goblin'),file));
// The installer's own key file, where it is now (in /etc/orbit before the migration moves it).
const etcKey=layoutPath('/etc/uptime-goblin/secret.key');
const exists=file=>{try{fs.statSync(onHost(file));return true;}catch{return false;}};
// A key file outside the data directory is root's to place (a link there is followed, as Uptime Goblin
// and systemd follow it), but none is waited on: opened without blocking (a FIFO would hold the
// installer for good), used only when it is a regular file, and at most 4096 bytes are read.
const read=(file,label)=>{
  let fd;
  try{fd=fs.openSync(onHost(file),fs.constants.O_RDONLY|fs.constants.O_NONBLOCK);}catch(e){refuse(`${label} cannot be read (${e.code||e.message}). ${nothing}`);}
  try{
    if(!fs.fstatSync(fd).isFile())refuse(`${label} is not a regular file, so it holds no key. Name the key file itself, then run this installer again. ${nothing}`);
    const buffer=Buffer.alloc(4097);let got=0;
    for(let n;got<buffer.length&&(n=fs.readSync(fd,buffer,got,buffer.length-got,null))>0;)got+=n;
    if(got>4096)refuse(`${label} is too large to hold a key. ${nothing}`);
    return buffer.subarray(0,got).toString('utf8');
  }catch(e){refuse(`${label} cannot be read (${e.code||e.message}). ${nothing}`);}
  finally{fs.closeSync(fd);}
};
const parse=(text,label)=>{try{return parseKey(text,label);}catch(e){refuse(`The encryption key from ${label} is not valid: ${e.message} ${nothing}`);}};
// systemd undoes C escapes in a SetCredential= value before it passes it ("\n" for a newline,
// man systemd.exec), as its cunescape() does: the text it passes, or null for an escape it
// refuses (it then ignores the line) or that is not decoded here (\u, \U), not checked then.
const cunescape=value=>{
  const named={a:'\x07',b:'\b',f:'\f',n:'\n',r:'\r',t:'\t',v:'\v',s:' ','\\':'\\','"':'"',"'":"'"};
  let text='';
  for(let i=0;i<value.length;i++){
    if(value[i]!=='\\'){text+=value[i];continue;}
    const m=/^(?:([abfnrtvs\\"'])|x([0-9a-fA-F]{2})|([0-3][0-7]{2}))/.exec(value.slice(i+1));
    if(!m)return null;
    text+=m[1]?named[m[1]]:String.fromCharCode(m[2]?parseInt(m[2],16):parseInt(m[3],8));
    i+=m[0].length;
  }
  return text;
};
// Files in the data directory belong to the uptime-goblin account, which can replace any of them with a
// symbolic link (to /etc/shadow, say) at any moment, also after this step read them. So root
// opens each of them once, never through a link (O_NOFOLLOW) and never waiting on a FIFO
// (O_NONBLOCK), only a regular file, and uses only what that one descriptor gave: the key copied
// to /etc/uptime-goblin below is the one checked here, never the file read again.
const shown=name=>`/var/lib/uptime-goblin/${name}`;
const present=name=>{try{fs.lstatSync(path.join(dataDir,name));return true;}catch(e){if(e.code==='ENOENT')return false;throw e;}};
const openData=name=>{
  let fd;
  try{fd=fs.openSync(path.join(dataDir,name),fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);}
  catch(e){if(e.code!=='ELOOP')throw e;}
  if(fd===undefined||!fs.fstatSync(fd).isFile()){
    if(fd!==undefined)fs.closeSync(fd);
    refuse(`${shown(name)} is ${fd===undefined?'a symbolic link':'not a regular file'}, which Uptime Goblin never makes. The installer runs as root, so in /var/lib/uptime-goblin, which the uptime-goblin account controls, it reads regular files only and never follows a link. Find out what put it there and put the real file in its place, then run this installer again. ${nothing}`);
  }
  return fd;
};
// At most copyLimit bytes, checked before and while copying (a file that grows meanwhile stops
// too): /tmp is often memory (tmpfs), and Uptime Goblin's control.sqlite is far smaller than this.
const copyLimit=2**30;
const copyData=(name,to)=>{
  const from=openData(name);
  try{
    if(fs.fstatSync(from).size>copyLimit)refuse(`${shown(name)} is larger than 1 GiB, more than the installer copies to check the encryption key against it. ${nothing} Stop Uptime Goblin (systemctl stop uptime-goblin), make room with its retention settings or ask for help, then run this installer again.`);
    const out=fs.openSync(to,'wx',0o600),buffer=Buffer.alloc(1<<20);
    let copied=0;
    try{for(let n;(n=fs.readSync(from,buffer))>0;){copied+=n;if(copied>copyLimit)refuse(`${shown(name)} grew past 1 GiB while the installer copied it. ${nothing}`);for(let at=0;at<n;)at+=fs.writeSync(out,buffer,at,n-at);}}finally{fs.closeSync(out);}
  }finally{fs.closeSync(from);}
};
// At most 4096 bytes, however large the file grows meanwhile.
const readDataKey=name=>{
  let fd;
  try{fd=openData(name);}catch(e){refuse(`${shown(name)} cannot be read (${e.code||e.message}). ${nothing}`);}
  try{
    const buffer=Buffer.alloc(4097);let got=0;
    for(let n;got<buffer.length&&(n=fs.readSync(fd,buffer,got,buffer.length-got,null))>0;)got+=n;
    if(got>4096)refuse(`${shown(name)} is too large to hold a key. ${nothing}`);
    return buffer.subarray(0,got).toString('utf8');
  }finally{fs.closeSync(fd);}
};
// A key file that /etc/uptime-goblin.env or a credential names is never read from the data directory
// either: the uptime-goblin account could turn it, or a directory on the way to it, into a link to any
// file (or a FIFO) at any moment, also after a check, and root reads it here (and systemd, as
// root, at every start for a credential); and every copy of the data directory would carry the
// key. So the name is followed as the kernel does, link by link from the real root, until a
// step of the way is in the data directory (a link from /etc into it included): that path, with
// the rest of the name as written, is returned (null when none is), before anything there is
// opened, and the name is refused.
const canonical=p=>{const rest=[];for(;;){try{return path.join(fs.realpathSync(p),...rest);}catch{const up=path.dirname(p);if(up===p)return path.join(p,...rest);rest.unshift(path.basename(p));p=up;}}};
const dataHome=canonical(dataDir);
const inDataHome=p=>p===dataHome||p.startsWith(dataHome+path.sep);
const inData=file=>{
  let parts=onHost(file).split('/').filter(Boolean),at='/',links=0;
  while(parts.length){
    const part=parts.shift();
    if(part==='.')continue;
    if(part==='..'){at=path.dirname(at);continue;}
    const next=path.join(at,part);
    if(inDataHome(next))return path.join(next,...parts);
    let target;
    // Not a link (EINVAL): a step of the way. Not there (or not a directory): the rest as written.
    try{target=fs.readlinkSync(next);}catch(e){if(e.code==='EINVAL'){at=next;continue;}const rest=path.join(next,...parts);return inDataHome(rest)?rest:null;}
    // A loop: opening it fails (ELOOP), as for Uptime Goblin.
    if(++links>40)return null;
    parts=[...target.split('/').filter(Boolean),...parts];
    if(target.startsWith('/'))at='/';
  }
  return inDataHome(at)?at:null;
};
// `kind`: what names the file: 'file' (GOBLIN_SECRET_KEY_FILE), 'previous', 'credential'
// (LoadCredential=), 'encrypted' (LoadCredentialEncrypted=, which only systemd reads) or 'etc'
// (/etc/uptime-goblin/secret.key, a link into the data directory). Naming the data directory's own
// secret.key, the way out is to name nothing: step 5 below then copies it out safely.
const refuseInData=(file,label,kind)=>{
  const at=inData(file);
  if(!at)return;
  const exact=at===path.join(dataHome,'secret.key');
  const what={file:'the GOBLIN_SECRET_KEY_FILE line from /etc/uptime-goblin.env (sudoedit /etc/uptime-goblin.env)',credential:'the LoadCredential line for orbit-secret-key from its drop-in (sudo systemctl edit uptime-goblin)',etc:'the link /etc/uptime-goblin/secret.key (sudo rm /etc/uptime-goblin/secret.key)'}[kind];
  const systemd=kind==='credential'||kind==='encrypted';
  const how=exact&&what
    ?`Remove ${what} and run this installer again: it then copies /var/lib/uptime-goblin/secret.key to /etc/uptime-goblin/secret.key (root:uptime-goblin, mode 0440), unless that file is already there, and names it in /etc/uptime-goblin.env.`
    :systemd
      ?'Move the credential to a file outside /var/lib/uptime-goblin that only root can read (in /etc/credstore, say), name that file in the drop-in instead (sudo systemctl edit uptime-goblin), then run this installer again.'
      :'Move the key to a file outside /var/lib/uptime-goblin that the uptime-goblin account can read (root:uptime-goblin, mode 0440, as /etc/uptime-goblin/secret.key is), name that file instead, then run this installer again.';
  const reader={credential:'systemd (as root, at every start of Uptime Goblin) and this installer',encrypted:'systemd (as root, at every start of Uptime Goblin)'}[kind]||'this installer, which runs as root,';
  const named=path.resolve(onHost(file)),written=named===path.resolve(dataDir)||named.startsWith(path.resolve(dataDir)+path.sep);
  refuse(`${label} ${written?'is in':'leads, through a link, into'} /var/lib/uptime-goblin, Uptime Goblin's data directory, which the uptime-goblin account controls: every copy of the data directory would carry the key, and ${reader} would read a file there that the uptime-goblin account can replace at any moment with a link to another file or a FIFO. ${how} ${nothing}`);
};
// GOBLIN_ names, the ORBIT_ ones from before the rename adopted as Uptime Goblin adopts them.
const env=envCurrent((()=>{try{return envValues(fs.readFileSync(envFile));}catch(e){if(e.code==='ENOENT')return envValues('');throw e;}})()).values;
// `reads`: the key files Uptime Goblin itself opens at every start, as the uptime-goblin account (systemd reads
// a credential as root); the step after the account exists checks that account can read each.
const plan={kind:null,file:null,reads:[],messages:[],warnings:[]};
const readBy=(file,label)=>plan.reads.push({file,label,path:onHost(file)});
(async()=>{
  // 0. Does the data have a keyring? Asked of a private copy; a read error never counts as "no".
  let copy=null,keyring=false;
  if(present('control.sqlite')){
    // Inside the installer's private directory (0700, removed on exit, a refusal included).
    const dir=path.join(path.dirname(planFile),'copy');
    fs.mkdirSync(dir,{mode:0o700});
    copy=path.join(dir,'control.sqlite');
    try{
      copyData('control.sqlite',copy);
      if(present('control.sqlite-wal'))copyData('control.sqlite-wal',copy+'-wal');
      keyring=(await inspectKeyring(copy)).keyring;
    }catch(e){refuse(`Could not tell whether Uptime Goblin's data in /var/lib/uptime-goblin has an encryption keyring (${e.code||e.errcode||e.name||'error'}). ${nothing} Run the installer again; if this repeats, stop Uptime Goblin first (systemctl stop uptime-goblin), then run it again.`);}
  }
  // The decrypt-only previous key, as Uptime Goblin reads it.
  let previous=null;
  if(env.GOBLIN_SECRET_KEY_PREVIOUS)previous=parse(env.GOBLIN_SECRET_KEY_PREVIOUS,'GOBLIN_SECRET_KEY_PREVIOUS in /etc/uptime-goblin.env');
  else if(env.GOBLIN_SECRET_KEY_PREVIOUS_FILE){
    const label=`GOBLIN_SECRET_KEY_PREVIOUS_FILE (${env.GOBLIN_SECRET_KEY_PREVIOUS_FILE})`;
    refuseInData(env.GOBLIN_SECRET_KEY_PREVIOUS_FILE,label,'previous');
    previous=parse(read(env.GOBLIN_SECRET_KEY_PREVIOUS_FILE,label),label);
    readBy(env.GOBLIN_SECRET_KEY_PREVIOUS_FILE,label);
  }
  // The key check: with a keyring, the key picked must open it.
  const check=async(key,label)=>{
    if(!keyring)return;
    let found;
    try{found=await inspectKeyring(copy,{key,previous});}catch(e){refuse(`Could not tell whether Uptime Goblin's data in /var/lib/uptime-goblin has an encryption keyring (${e.code||e.errcode||e.name||'error'}). ${nothing} Run the installer again; if this repeats, stop Uptime Goblin first (systemctl stop uptime-goblin), then run it again.`);}
    if(found.matches===false)refuse(`The encryption key from ${label} (fingerprint ${keyFingerprint(key)}) does not open Uptime Goblin's data in /var/lib/uptime-goblin. Restore the key that data was created with (see 'Encryption key' in docs/installation.md) and run this installer again. ${nothing}`);
  };
  // The systemd credential, from `systemctl cat`: the unit, then its drop-ins, each after a
  // "# <path>" line, read as systemd reads them (man systemd.exec). It keeps two lists:
  // LoadCredential= with LoadCredentialEncrypted=, and SetCredential= with
  // SetCredentialEncrypted=. In each the last assignment of the name counts, and an empty
  // assignment clears that list only (as systemd 257 does). A Load* credential outranks a Set*
  // one, which systemd uses only when there is none or its file cannot be read. This installer
  // replaces the unit itself with its own uptime-goblin.service, so after it only what the drop-ins set
  // counts (`kept`).
  // A header names a unit file or a drop-in (.conf); a comment in a file is not one.
  const headerOf=line=>/^# (\/\S+\.(?:service|conf))$/.exec(line)?.[1];
  const unitPath=unitText.map(headerOf).find(file=>file&&!file.endsWith('.conf'))||layoutPath('/etc/systemd/system/uptime-goblin.service');
  // `file`: the unit file or drop-in that sets it, for the messages.
  const listsOf=dropInsOnly=>{
    const found={load:null,set:null};
    let dropIn=false,file=unitPath;
    for(const line of unitText){
      const header=headerOf(line);
      if(header){dropIn=header.endsWith('.conf');file=header;continue;}
      if(dropInsOnly&&!dropIn)continue;
      const m=/^\s*(LoadCredential|LoadCredentialEncrypted|SetCredential|SetCredentialEncrypted)\s*=\s*(.*)$/.exec(line);
      if(!m)continue;
      const value=m[2].trim(),list=m[1].startsWith('Load')?'load':'set';
      if(!value){found[list]=null;continue;}
      const at=value.indexOf(':'),name=at<0?value:value.slice(0,at),rest=at<0?'':value.slice(at+1);
      if(name==='orbit-secret-key')found[list]={setting:m[1],value:rest,file};
    }
    return found;
  };
  // The one systemd passes. A Load* file named by an absolute path that is not there falls back
  // to the Set* value; one found by name (no path, or a relative one) is taken to be there.
  const credentialOf=({load,set})=>load&&!(set&&path.isAbsolute(load.value)&&!exists(load.value))?load:set;
  const lists=listsOf(false),keptLists=listsOf(true);
  const credential=credentialOf(lists),kept=credentialOf(keptLists);
  // A SetCredential= value is the key itself: it is never printed, only the setting's name.
  const assignment=c=>`${c.setting}=orbit-secret-key${c.setting.startsWith('Set')?':…':c.value?`:${c.value}`:''}`;
  // ImportCredential= outranks SetCredential= too, with what it finds in the credential stores;
  // this installer does not look there, so beside one a SetCredential= key is not checked.
  const imports=unitText.some(line=>/^\s*ImportCredential\s*=\s*\S/.test(line));
  if(env.GOBLIN_SECRET_KEY){
    // 1. In the environment file: kept, but Uptime Goblin's process environment shows it.
    await check(parse(env.GOBLIN_SECRET_KEY,'GOBLIN_SECRET_KEY in /etc/uptime-goblin.env'),'GOBLIN_SECRET_KEY in /etc/uptime-goblin.env');
    plan.kind='env';
    plan.warnings.push("WARNING: GOBLIN_SECRET_KEY in /etc/uptime-goblin.env puts the key in Uptime Goblin's process environment, which root and the uptime-goblin user can read in /proc/<pid>/environ. Move it to a file: see 'Encryption key' in docs/installation.md.");
  }else if(env.GOBLIN_SECRET_KEY_FILE){
    // 2. A key file the environment file names: kept; it must exist, outside the data directory.
    const file=env.GOBLIN_SECRET_KEY_FILE;
    refuseInData(file,`GOBLIN_SECRET_KEY_FILE (${file})`,'file');
    if(!exists(file))refuse(`GOBLIN_SECRET_KEY_FILE in /etc/uptime-goblin.env names ${file}, which does not exist. Restore the key file from your backup where the uptime-goblin account can read it (sudo install -o root -g uptime-goblin -m 0440 KEY_BACKUP_FILE ${shellWord(file)}, with KEY_BACKUP_FILE replaced by the path of your backup), or remove the line to let the installer create a new key for data that has none yet, then run this installer again. ${nothing}`);
    const label=`GOBLIN_SECRET_KEY_FILE (${file})`;
    await check(parse(read(file,label),label),label);
    plan.kind='file';plan.file=file;
    readBy(file,label);
  }else if(credential){
    // 3. The systemd credential: kept, and no line (GOBLIN_SECRET_KEY_FILE would outrank it). Set
    // in the unit itself it would be gone with the unit this installer writes: a 1.4.x upgrade
    // would then generate /var/lib/uptime-goblin/secret.key, and a 1.5 one refuse to start (key_missing)
    // with no unit to roll back to. So it must be in a drop-in, which the installer leaves alone.
    if(!kept||kept.setting!==credential.setting||kept.value!==credential.value)refuse(`The systemd credential orbit-secret-key is set in ${unitPath} itself (${assignment(credential)}), which this installer replaces with its own uptime-goblin.service, so Uptime Goblin would lose its key. Move that line into a drop-in (sudo systemctl edit uptime-goblin), then run this installer again. ${nothing}`);
    plan.kind='credential';
    // systemd reads an absolute path as root at every start, an encrypted one too, and also
    // when a SetCredential= value stands in for a file that is not there yet.
    const load=keptLists.load;
    if(load&&path.isAbsolute(load.value))refuseInData(load.value,`The systemd credential orbit-secret-key (${load.value})`,load.setting==='LoadCredential'?'credential':'encrypted');
    const file=credential.setting==='LoadCredential'&&path.isAbsolute(credential.value)?credential.value:null;
    const text=credential.setting==='SetCredential'&&!imports?cunescape(credential.value):null;
    if(file){
      const label=`the systemd credential orbit-secret-key (${file})`;
      await check(parse(read(file,label),label),label);
      plan.messages.push(`Encryption key: the systemd credential orbit-secret-key (${file}).`);
    }else if(text!==null){
      // The installer holds the key text itself: checked like a key file, before anything stops.
      const label=`the systemd credential orbit-secret-key (SetCredential= in ${credential.file})`;
      await check(parse(text,label),label);
      plan.messages.push(`Encryption key: ${label}.`);
    }else plan.messages.push(`Encryption key: the systemd credential orbit-secret-key (${credential.setting}). It could not be checked against the data; Uptime Goblin checks it at start.`);
  }else if(exists(etcKey)){
    // 4. The installer's key file from an earlier run: named in /etc/uptime-goblin.env.
    refuseInData(etcKey,'/etc/uptime-goblin/secret.key','etc');
    await check(parse(read(etcKey,'/etc/uptime-goblin/secret.key'),'/etc/uptime-goblin/secret.key'),'/etc/uptime-goblin/secret.key');
    plan.kind='append';plan.file=etcKey;
    readBy(etcKey,'/etc/uptime-goblin/secret.key');
  }else if(present('secret.key')){
    // 5. A key Uptime Goblin generated in the data directory: copied out of it. What goes to /etc/uptime-goblin
    // is the key checked here, as Uptime Goblin writes one (64 hex digits and a newline), kept in the
    // installer's private directory for the step that writes it. The data directory's copy is
    // left for goblin-admin key remove-data-copy, whose line the message gives (A67): it deletes
    // that file only while /etc/uptime-goblin/secret.key holds the same key and opens the data.
    const key=parse(readDataKey('secret.key'),shown('secret.key'));
    await check(key,shown('secret.key'));
    // The private copy of the data goes before the key is written: the key on disk is never
    // beside a copy of the data it opens (a run killed here would leave both in /tmp), as the
    // unit's text, which a SetCredential= line puts the key in, is gone before the copy is made.
    if(copy){fs.rmSync(path.dirname(copy),{recursive:true,force:true});copy=null;}
    fs.writeFileSync(path.join(path.dirname(planFile),'data.key'),key.toString('hex')+'\n',{mode:0o600,flag:'wx'});
    key.fill(0);
    plan.kind='copy';plan.file=etcKey;
    plan.messages.push('Copied the encryption key to /etc/uptime-goblin/secret.key. Back that file up separately. Once Uptime Goblin has started, delete /var/lib/uptime-goblin/secret.key, which would otherwise travel with every backup of the data directory, with this line, which deletes it only while /etc/uptime-goblin/secret.key holds the same key and opens the data: sudo -u uptime-goblin env GOBLIN_SECRET_KEY_FILE=/etc/uptime-goblin/secret.key node /opt/uptime-goblin/lib/cli/goblin-admin.mjs key remove-data-copy --data-dir /var/lib/uptime-goblin');
  }else if(keyring){
    // 6. Encrypted data whose key is nowhere on this host.
    refuse(`Uptime Goblin's data in /var/lib/uptime-goblin is encrypted with a key that is not on this host (no GOBLIN_SECRET_KEY, GOBLIN_SECRET_KEY_FILE, systemd credential, /etc/uptime-goblin/secret.key or /var/lib/uptime-goblin/secret.key). Restore /etc/uptime-goblin/secret.key from your backup where the uptime-goblin account can read it (sudo install -d -o root -g uptime-goblin -m 0750 /etc/uptime-goblin, then sudo install -o root -g uptime-goblin -m 0440 KEY_BACKUP_FILE /etc/uptime-goblin/secret.key, with KEY_BACKUP_FILE replaced by the path of your backup) and run this installer again. Only if the key is truly lost: see 'Lost encryption key' in docs/troubleshooting.md. ${nothing}`);
  }else{
    // 7. Nothing yet: a new key.
    plan.kind='generate';plan.file=etcKey;
    plan.messages.push('Created the encryption key /etc/uptime-goblin/secret.key. Back it up separately from /var/lib/uptime-goblin: without it Uptime Goblin cannot open what it has sealed.');
  }
  // A SetCredential= key is plain text in a drop-in, which `systemctl edit` makes readable by
  // every local account (0644): more exposed than GOBLIN_SECRET_KEY in /etc/uptime-goblin.env (root's,
  // 0600), which is warned about above. Said whatever outranks it: the key text is still there.
  const set=keptLists.set;
  if(set?.setting==='SetCredential')plan.warnings.push(`WARNING: SetCredential=orbit-secret-key in ${set.file} keeps Uptime Goblin's encryption key in plain text: a drop-in made with sudo systemctl edit can be read by every local account (mode 0644), and systemd's manual says not to use SetCredential= for secrets. Put the key in a file only root can read and name it instead (LoadCredential=orbit-secret-key:/etc/credstore/orbit-secret-key), or encrypt it (SetCredentialEncrypted=), then remove the SetCredential= line: see 'Encryption key' in docs/installation.md.`);
  if(previous)previous.fill(0);
  if(copy)fs.rmSync(path.dirname(copy),{recursive:true,force:true});
  fs.writeFileSync(planFile,JSON.stringify(plan),{mode:0o600,flag:'wx'});
})().catch(e=>refuse(`The encryption key could not be checked (${e.code||e.message}). ${nothing}`));
NODE
} | "$goblin_node" - "$goblin_cur_env" "$goblin_root" "$goblin_cur_data" "$goblin_key_dir/unit.txt" "$goblin_source" "$goblin_key_dir/plan.json" || exit 1
goblin_key_plan=$("$goblin_node" -p 'require(process.argv[1]).kind' "$goblin_key_dir/plan.json")
goblin_key_file=$("$goblin_node" -p 'require(process.argv[1]).file||""' "$goblin_key_dir/plan.json")
printf 'Preparing pinned application dependencies…\n'
goblin_deps=$(mktemp -d /tmp/uptime-goblin-dependencies.XXXXXX)
goblin_unit_stage=
# Set once this release's unit replaced the one on disk; only then does a rollback swap in
# rollback.service, so an old unit that was never replaced stays as it was.
goblin_unit_published=
goblin_cleanup() {
  rm -rf -- "$goblin_deps" "$goblin_stage" "$goblin_key_dir"
  if [[ -n $goblin_unit_stage ]]; then rm -rf -- "$goblin_unit_stage"; fi
}
trap goblin_cleanup EXIT
install -m 644 "$goblin_source/package.json" "$goblin_source/package-lock.json" "$goblin_deps/"
"$goblin_npm" ci --prefix "$goblin_deps" --omit=dev --ignore-scripts --no-audit --no-fund
printf 'Preparing Uptime Goblin account and storage…\n'
# The account of the layout in place: orbit on a host with the Orbit layout, which the migration
# renames to uptime-goblin (its files keep their owner), else uptime-goblin.
getent group "$goblin_account" >/dev/null || groupadd --system "$goblin_account"
id "$goblin_account" >/dev/null 2>&1 || useradd --system --gid "$goblin_account" --home "${goblin_cur_app#"$goblin_root"}" --shell /usr/sbin/nologin "$goblin_account"
# Uptime Goblin opens its key file as the uptime-goblin account at every start and refuses to start without it
# (exit status 78, key_file_unreadable); the key step above read it as root, which proves nothing
# for that account. A key restored the way its backup was made (sudo install -m 600 …) is
# root:root 0600, and the upgrade would then stop Uptime Goblin, fail its verification and roll back to
# code that fails the same way. So, now that the account exists and before the service stops:
# the installer's own /etc/uptime-goblin/secret.key goes back to what the step that creates it writes,
# root:uptime-goblin 0440 in /etc/uptime-goblin (root:uptime-goblin 0750), unless either is a link (left as it is); then
# each key file Uptime Goblin opens is tried as the uptime-goblin account (runuser, from util-linux), and one it
# cannot read refuses with nothing else changed. (The unit's sandbox also hides home directories
# and /tmp from Uptime Goblin; that is not checked here.)
# (Before the migration: /etc/orbit/secret.key, root:orbit.)
goblin_shown_key_home=${goblin_cur_key_home#"$goblin_root"}
if [[ ($goblin_key_plan == file || $goblin_key_plan == append) && $goblin_key_file == "$goblin_shown_key_home/secret.key" &&
  -d $goblin_cur_key_home && ! -L $goblin_cur_key_home && -f $goblin_cur_key_home/secret.key && ! -L $goblin_cur_key_home/secret.key ]]; then
  goblin_key_modes() {
    "$goblin_node" -e 'for(const file of process.argv.slice(1)){const s=require("node:fs").statSync(file);console.log(s.uid,s.gid,(s.mode&0o7777).toString(8));}' "$goblin_cur_key_home" "$goblin_cur_key_home/secret.key"
  }
  goblin_key_was=$(goblin_key_modes)
  { chown "root:$goblin_account" "$goblin_cur_key_home" "$goblin_cur_key_home/secret.key" && chmod 0750 "$goblin_cur_key_home" && chmod 0440 "$goblin_cur_key_home/secret.key"; } ||
    goblin_fail "Could not give $goblin_shown_key_home/secret.key to root:$goblin_account, mode 0440. Uptime Goblin was not changed; fix the problem and run this installer again."
  [[ $(goblin_key_modes) == "$goblin_key_was" ]] ||
    printf 'Gave %s/secret.key to root:%s, mode 0440, in %s (root:%s, mode 0750), so that the %s account Uptime Goblin runs as can read it.\n' "$goblin_shown_key_home" "$goblin_account" "$goblin_shown_key_home" "$goblin_account" "$goblin_account"
fi
# accountReads(path) runs `test -r <path>` as the uptime-goblin account (runuser, from util-linux): true when
# that account can read it, false when test says it cannot (exit status 1, nothing on stderr: test
# writes nothing), and otherwise how runuser itself failed, as a phrase. runuser also exits 1 for
# errors of its own before it runs test (a PAM session it cannot open, say), but it says so on
# stderr; 126 and 127 mean test could not be run. Such a failure is never taken for an unreadable
# file, whose chown would not help: it refuses with runuser's own words.
goblin_reads_js=$(cat <<'NODE'
const accountReads=path=>{
  const tried=require('node:child_process').spawnSync('runuser',['-u',process.env.goblin_account,'--','test','-r',path],{stdio:['ignore','ignore','pipe'],encoding:'utf8'});
  if(tried.error)return `could not be run (${tried.error.code})`;
  if(tried.status===0)return true;
  const said=String(tried.stderr??'').replace(/[\s\x00-\x1f\x7f]+/g,' ').trim().slice(0,500);
  if(tried.status===1&&!said)return false;
  return `${tried.signal?`was stopped by ${tried.signal}`:`exited with status ${tried.status}`}${said?` (${said})`:''}`;
};
NODE
)
{
  printf '%s\n' "$goblin_env_js" "$goblin_reads_js"
  cat <<'NODE'
for(const {file,label,path} of require(process.argv[2]).reads){
  const reads=accountReads(path);
  if(typeof reads==='string'){console.error(`Could not check that the uptime-goblin account can read ${label}: runuser (from util-linux) ${reads}. Uptime Goblin was not changed.`);process.exit(1);}
  if(!reads){console.error(`${label} cannot be read by the uptime-goblin account, which Uptime Goblin runs as, so Uptime Goblin would refuse to start (exit status 78, key_file_unreadable). Let the group uptime-goblin read it: sudo chown root:uptime-goblin ${shellWord(file)} && sudo chmod 0440 ${shellWord(file)}, in a directory the uptime-goblin account can enter (as /etc/uptime-goblin is, root:uptime-goblin 0750), then run this installer again. Uptime Goblin was not changed.`);process.exit(1);}
}
NODE
} | "$goblin_node" - "$goblin_key_dir/plan.json" || exit 1
install -d -o root -g root -m 755 "$goblin_root/opt"
install -d -o "$goblin_account" -g "$goblin_account" -m 700 "$goblin_cur_data"
# auth.json: the password step above read it as root, which proves nothing for the uptime-goblin account
# Uptime Goblin runs as, just as for the key files. One that account cannot read (a backup copied in as
# root, root:root 0600) makes every start of Uptime Goblin fail (exit status 1, which systemd retries),
# so an upgrade would stop Uptime Goblin, fail its verification and roll back to code that cannot read it
# either, and an install with no previous version would leave Uptime Goblin down. So, now that the data
# directory is the uptime-goblin account's and before the service stops or /etc/uptime-goblin.env changes, an
# auth.json there is tried as the uptime-goblin account (runuser, from util-linux), and one it cannot
# read refuses, with the fix (accountReads(), above: a failure of runuser itself refuses with its
# own words instead).
if [[ -e $goblin_cur_data/auth.json ]]; then
  {
    printf '%s\n' "$goblin_env_js" "$goblin_reads_js"
    cat <<'NODE'
const kept='Uptime Goblin was not stopped, and its code and settings were not changed.';
const reads=accountReads(process.argv[2]);
if(typeof reads==='string'){console.error(`Could not check that the uptime-goblin account can read /var/lib/uptime-goblin/auth.json: runuser (from util-linux) ${reads}. ${kept}`);process.exit(1);}
if(!reads){console.error(`/var/lib/uptime-goblin/auth.json cannot be read by the uptime-goblin account, which Uptime Goblin runs as, so Uptime Goblin would fail to start (exit status 1), and systemd would start it again every 5 seconds. Give it to that account: sudo chown uptime-goblin:uptime-goblin /var/lib/uptime-goblin/auth.json && sudo chmod 0600 /var/lib/uptime-goblin/auth.json, then run this installer again. ${kept}`);process.exit(1);}
NODE
  } | "$goblin_node" - "$goblin_cur_data/auth.json" || exit 1
fi
# The settings file of the layout in place, with its names (ORBIT_ in /etc/orbit.env, which the
# migration then writes as /etc/uptime-goblin.env with GOBLIN_ names).
goblin_shown_env=${goblin_cur_env#"$goblin_root"}
if [[ ! -e $goblin_cur_env ]]; then
  "$goblin_node" - "$goblin_cur_env" "$goblin_host" "$goblin_hosts" "$goblin_env_prefix" <<'NODE'
const fs=require('node:fs'),crypto=require('node:crypto'),prefix=process.argv[5];
fs.writeFileSync(process.argv[2],`HOST=${process.argv[3]}\nPORT=4317\n${prefix}ALLOWED_HOSTS=${process.argv[4]}\n${prefix}PASSWORD=${crypto.randomBytes(24).toString('base64url')}\n`,{mode:0o600,flag:'wx'});
NODE
  printf 'Created private settings in %s. Sign in as admin with %sPASSWORD from that file.\n' "$goblin_shown_env" "$goblin_env_prefix"
else
  printf 'Preserving existing %s and all saved connections/history.\n' "$goblin_shown_env"
  # Said, not done silently: these two only write a new /etc/uptime-goblin.env.
  if [[ -n $goblin_listen_given || -n $goblin_hosts_given ]]; then
    printf 'Not applied: --listen and --allowed-hosts only fill in a new %s. Edit HOST= or %sALLOWED_HOSTS= in %s (sudoedit %s), then run this installer again.\n' "$goblin_shown_env" "$goblin_env_prefix" "$goblin_shown_env" "$goblin_shown_env" >&2
  fi
fi
# Apply --trust-proxy/--allow-loopback to new and existing settings (--trust-proxy off empties
# the line), and warn when a proxied install would share one sign-in lockout between every
# client. --allow-insecure-http adds GOBLIN_INSECURE_HTTP_SESSIONS=1, with a comment that says who
# chose it and that passwords then cross the network in clear, and a warning, only where neither
# /etc/uptime-goblin.env nor anything else systemd would give Uptime Goblin says yes or no (systemd's view as
# worked out before anything changed, $goblin_given): a yes is kept, and so is a no, with a notice
# that the option was not applied, naming where systemd takes it from when that is not
# /etc/uptime-goblin.env (a drop-in's Environment= or systemd's own environment, which a line added to the
# file would override, as systemd reads EnvironmentFile= after them). Nothing else adds that
# line: the plain-HTTP preflight above stopped every install that would need it, and a line
# someone removed is never added again. The =1 an earlier 1.5 pre-release installer added by
# itself decides nothing (envPreReleaseOptIn()): the option keeps that line and puts its own
# comment in place of the one written with it. Without the option no install gets here with that
# line: the plain-HTTP step stopped it. The warning about a public host takes GOBLIN_TRUST_PROXY
# and GOBLIN_INSECURE_HTTP_SESSIONS as systemd would give them to Uptime Goblin, with this step's changes.
{
  printf '%s\n' "$goblin_env_js"
  cat <<'NODE'
const fs=require('node:fs'),file=process.argv[2],source=process.argv[5],allowInsecure=process.argv[6]==='1',systemd=JSON.parse(process.argv[7]);
// A rewrite below ends every line with LF, also one that ended in CRLF or in a CR alone:
// systemd takes each of the three for the end of a line, so what it passes Uptime Goblin is unchanged.
const lines=envLines(fs.readFileSync(file,'utf8'));if(lines.at(-1)==='')lines.pop();
// --trust-proxy off (0, false, no) turns proxy trust off: an empty value, as Uptime Goblin reads it.
const updates={};if(process.argv[3])updates.GOBLIN_TRUST_PROXY=proxyOn(process.argv[3],source)?process.argv[3]:'';if(process.argv[4])updates.GOBLIN_ALLOW_LOOPBACK='1';
// The assignment that takes effect is the last: rewrite that one (an earlier one stays overridden).
// Under its GOBLIN_ name, its ORBIT_ name from before the rename, or both, as the file has them (both
// rewritten, they stay equal, as Uptime Goblin requires); a line added takes the names of the layout
// in place (goblin_env_prefix: ORBIT_ in /etc/orbit.env, which the migration renames).
const changed=[],written=[];for(const [key,value]of Object.entries(updates)){const at=[envLastLine(lines,key),envLastLine(lines,'ORBIT_'+key.slice(7))].filter(i=>i>=0);if(at.length&&at.every(i=>envAssignment(lines[i]).value===value))continue;if(!at.length&&value==='')continue;changed.push(key);if(at.length)for(const i of at){const name=envAssignment(lines[i]).key;written.push(name);lines[i]=name+'='+value;}else{const name=process.env.goblin_env_prefix+key.slice(7);written.push(name);lines.push(name+'='+value);}}
const value=key=>envCurrent(envValues(lines.join('\n'))).values[key]??'';
// --trust-proxy is applied in systemd.trustProxy as above.
const host=value('HOST')||'127.0.0.1',warnings=[],proxy=proxyOn(systemd.trustProxy,source);
const {flagValue}=require(require('node:path').join(source,'lib/environment.mjs'));
const preRelease=envPreReleaseOptIn(lines);
const decided=preRelease<0?flagValue(value('GOBLIN_INSECURE_HTTP_SESSIONS')):null;
if(allowInsecure&&preRelease<0&&systemd.insecure===false)warnings.push(systemd.insecureFrom===null?'Not applied: --allow-insecure-http adds GOBLIN_INSECURE_HTTP_SESSIONS=1 only to an /etc/uptime-goblin.env that does not set it, and yours turns it off, so sign-in over plain HTTP stays refused. To allow it, set that line to 1 (sudoedit /etc/uptime-goblin.env) and restart Uptime Goblin (sudo systemctl restart uptime-goblin.service).':`Not applied: --allow-insecure-http adds GOBLIN_INSECURE_HTTP_SESSIONS=1 to /etc/uptime-goblin.env only where systemd would give Uptime Goblin no yes or no for it, and it would give Uptime Goblin one that turns it off (${systemd.insecureFrom}), so sign-in over plain HTTP stays refused. To allow it, set it to 1 there (a drop-in: sudo systemctl edit uptime-goblin) and restart Uptime Goblin (sudo systemctl restart uptime-goblin.service).`);
else if(allowInsecure&&(preRelease>=0||(systemd.insecure===null&&typeof decided!=='boolean'))){
const who=/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}$/.test(process.env.SUDO_USER||'')?process.env.SUDO_USER:'root';
const comment=`# Added by the Uptime Goblin installer on ${new Date().toISOString().slice(0,10)} because ${who} ran it with --allow-insecure-http: sign-in over plain HTTP, so passwords and the sign-in cookie cross the network in clear. Set it to 0 once Uptime Goblin is served over HTTPS.`;
if(preRelease>=0){lines[preRelease]=comment;written.push(envAssignment(lines[preRelease+1]).key);}else{const name=process.env.goblin_env_prefix+'INSECURE_HTTP_SESSIONS';lines.push(comment,name+'=1');written.push(name);}changed.push('GOBLIN_INSECURE_HTTP_SESSIONS');
warnings.push(`WARNING: --allow-insecure-http ${preRelease>=0?'kept GOBLIN_INSECURE_HTTP_SESSIONS=1 in /etc/uptime-goblin.env, which an earlier 1.5 pre-release installer had added, as your choice':'added GOBLIN_INSECURE_HTTP_SESSIONS=1 to /etc/uptime-goblin.env'}: Uptime Goblin allows sign-in over plain HTTP, so your network can see the sign-in cookie, the password each time you sign in or change it, and the password of every script that signs in with HTTP Basic. Serve Uptime Goblin over HTTPS, then set GOBLIN_INSECURE_HTTP_SESSIONS=0 in /etc/uptime-goblin.env and restart Uptime Goblin (sudo systemctl restart uptime-goblin.service).`);}
if(changed.length){const tmp=file+'.goblin-tmp';try{fs.unlinkSync(tmp);}catch{}fs.writeFileSync(tmp,lines.join('\n')+'\n',{mode:0o600,flag:'wx'});fs.renameSync(tmp,file);console.log('Updated '+written.join(' and ')+' in /etc/uptime-goblin.env.');}
for(const warning of warnings)console.warn(warning);
const proxied=value('GOBLIN_ALLOWED_HOSTS').split(',').map(h=>h.trim()).some(h=>h&&!/^(localhost|127\.\d+\.\d+\.\d+|\[::1\])(:\d+)?$/i.test(h));
// Without a trusted proxy Uptime Goblin cannot believe X-Forwarded-Proto, so a browser behind the proxy
// is plain HTTP to it (a proxy that sends no forwarding headers too) and its sign-in is refused.
// An ssh tunnel reaches Uptime Goblin on the Uptime Goblin host's loopback, where Uptime Goblin counts it as a browser on
// the host itself: to 127.0.0.1 when Uptime Goblin listens there (HOST 127.0.0.1, the default) or on
// every address (0.0.0.0, ::), to [::1] or localhost when HOST names that. An install made with
// --listen <address> listens on no loopback address, and a tunnel to its address is plain HTTP
// to Uptime Goblin (docs audit, install-changelog 5).
const plainAllowed=systemd.insecure===true||changed.includes('GOBLIN_INSECURE_HTTP_SESSIONS');
// [::1] is quoted, or zsh would take its brackets for a file pattern.
const port=value('PORT')||'4317',target=new Map([['127.0.0.1','127.0.0.1'],['0.0.0.0','127.0.0.1'],['::','127.0.0.1'],['::1','[::1]'],['localhost','localhost']]).get(host),tunnel=target&&(target==='[::1]'?`'${port}:[::1]:${port}'`:`${port}:${target}:${port}`),inClear=' (the password and the sign-in cookie then cross it unencrypted)';
if(proxied&&!proxy)console.warn(`WARNING: GOBLIN_ALLOWED_HOSTS names a public host but GOBLIN_TRUST_PROXY is not set. Behind a reverse proxy, every client then shares one sign-in lockout${plainAllowed?'':', and Uptime Goblin cannot tell that browsers use HTTPS, so it refuses their sign-in through the proxy'}. Re-run with --trust-proxy loopback (proxy on this host) or --trust-proxy <proxy address>, and make the proxy send X-Forwarded-For and X-Forwarded-Proto (nginx: proxy_set_header X-Forwarded-Proto $scheme;).${plainAllowed?'':tunnel?` Until then, sign in through ssh -L ${tunnel} and http://localhost:${port}, or add GOBLIN_INSECURE_HTTP_SESSIONS=1 to /etc/uptime-goblin.env on a network you trust${inClear}.`:` Until then, add GOBLIN_INSECURE_HTTP_SESSIONS=1 to /etc/uptime-goblin.env on a network you trust${inClear}: Uptime Goblin listens on ${host}, so an ssh tunnel to 127.0.0.1 does not reach it, and one to ${host} is plain HTTP to Uptime Goblin.`}`);
NODE
} | "$goblin_node" - "$goblin_cur_env" "$goblin_trust_proxy" "$goblin_allow_loopback" "$goblin_source" "$goblin_allow_insecure_http" "$goblin_given"
# The encryption key (decided above, before anything changed): a key file copied out of the
# data directory or newly generated goes to /etc/uptime-goblin (root:uptime-goblin 0440 in a 0750 directory, so
# the service account can read it under ProtectSystem=strict), written to a temporary file that
# is synced before the rename, the directory synced after; only then is it named in
# /etc/uptime-goblin.env, so a power cut never leaves an environment that names a missing key. A key
# copied out of the data directory comes from the installer's private directory, where the
# plan put the key it checked: /var/lib/uptime-goblin/secret.key is never opened again, since the uptime-goblin
# account could have replaced it with a link to any file root can read.
if [[ $goblin_key_plan == copy || $goblin_key_plan == generate ]]; then
  install -d -o root -g "$goblin_account" -m 0750 "$goblin_cur_key_home"
  goblin_key_tmp=$(mktemp "$goblin_cur_key_home/.secret.key.XXXXXX")
  goblin_key_failed() {
    rm -f -- "$goblin_key_tmp"
    goblin_fail "Could not write $goblin_shown_key_home/secret.key ($1). Uptime Goblin was not changed; fix the problem and run this installer again."
  }
  if [[ $goblin_key_plan == copy ]]; then
    cat -- "$goblin_key_dir/data.key" >"$goblin_key_tmp" || goblin_key_failed 'copy'
  else
    "$goblin_node" -e 'process.stdout.write(require("node:crypto").randomBytes(32).toString("hex")+"\n")' >"$goblin_key_tmp" || goblin_key_failed 'generate'
  fi
  chown "root:$goblin_account" "$goblin_key_tmp" && chmod 0440 "$goblin_key_tmp" || goblin_key_failed 'permissions'
  sync "$goblin_key_tmp" || goblin_key_failed 'sync'
  if [[ $goblin_key_plan == copy ]] && ! cmp -s -- "$goblin_key_dir/data.key" "$goblin_key_tmp"; then
    goblin_key_failed 'the copy differs from the key that was checked'
  fi
  mv -- "$goblin_key_tmp" "$goblin_cur_key_home/secret.key" || goblin_key_failed 'rename'
  sync "$goblin_cur_key_home" || goblin_fail "Could not sync $goblin_shown_key_home after writing secret.key. Run this installer again."
  rm -f -- "$goblin_key_dir/data.key"
fi
if [[ $goblin_key_plan == copy || $goblin_key_plan == generate || $goblin_key_plan == append ]]; then
  {
    printf '%s\n' "$goblin_env_js"
    cat <<'NODE'
const fs=require('node:fs'),[file,prefix,keyFile]=process.argv.slice(2);
// Split as the rewrite above splits it (envLines): every line then ends with LF, also one that
// ended in CRLF or in a CR alone, which systemd reads alike. Split on LF alone, a CRLF file kept
// its CRs beside the two LF lines added here.
const lines=envLines(fs.readFileSync(file,'utf8'));if(lines.at(-1)==='')lines.pop();
lines.push("# Added by the Uptime Goblin 1.5 installer: the encryption key for Uptime Goblin's sealed settings. Back it up separately.",`${prefix}SECRET_KEY_FILE=${keyFile}`);
const tmp=file+'.goblin-tmp';try{fs.unlinkSync(tmp);}catch{}fs.writeFileSync(tmp,lines.join('\n')+'\n',{mode:0o600,flag:'wx'});fs.renameSync(tmp,file);
console.log(`Updated ${prefix}SECRET_KEY_FILE in /etc/uptime-goblin.env.`);
NODE
  } | "$goblin_node" - "$goblin_cur_env" "$goblin_env_prefix" "$goblin_shown_key_home/secret.key"
fi
# What the key step did and found. With the Orbit layout, said once the migration is done, under
# the names it then has.
goblin_key_messages() {
  "$goblin_node" -e 'const plan=require(process.argv[1]);for(const line of plan.messages)console.log(line);for(const line of plan.warnings)console.warn(line);' "$goblin_key_dir/plan.json"
}
[[ $goblin_layout == orbit ]] || goblin_key_messages
# Build the complete new tree next to the running one, so the switch is two renames and the
# previous tree stays intact for a rollback.
printf 'Staging application files…\n'
rm -rf -- "$goblin_stage"
install -d -o root -g root -m 755 "$goblin_stage"
for goblin_file in "${goblin_files[@]}"; do
  install -d -o root -g root -m 755 "$goblin_stage/$(dirname -- "$goblin_file")"
  install -o root -g root -m 644 "$goblin_source/$goblin_file" "$goblin_stage/$goblin_file"
done
cp -R "$goblin_deps/node_modules" "$goblin_stage/node_modules"
chown -R root:root "$goblin_stage/node_modules"
chmod -R a+rX "$goblin_stage/node_modules"
goblin_version=$("$goblin_node" -p 'require(process.argv[1]).version' "$goblin_stage/package.json")
goblin_build=$("$goblin_node" "$goblin_stage/lib/healthcheck.mjs" --print-build "$goblin_stage")
[[ $goblin_version =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$ && $goblin_build =~ ^[0-9a-f]{12}$ ]] || goblin_fail 'Could not determine the version and build being installed.'
# Repairing the same release must not replace an older rollback copy with another copy of
# the current release. Hold this installation separately until the repair has been verified.
goblin_rollback=$goblin_previous
if [[ -f $goblin_app/server.mjs ]] &&
  [[ $("$goblin_node" "$goblin_stage/lib/healthcheck.mjs" --print-build "$goblin_app" 2>/dev/null || true) == "$goblin_build" ]] &&
  cmp -s "$goblin_app/package.json" "$goblin_stage/package.json" &&
  cmp -s "$goblin_app/package-lock.json" "$goblin_stage/package-lock.json" &&
  cmp -s "$goblin_app/deploy/manifest.txt" "$goblin_stage/deploy/manifest.txt"; then
  goblin_rollback=$goblin_reinstall
fi
# Report a service that could no longer start because its Node binary moved or was removed.
if [[ -f $goblin_cur_unit ]]; then
  goblin_old_node=$(sed -n 's/^ExecStart=\([^ ]*\).*/\1/p' "$goblin_cur_unit" | head -n 1)
  if [[ -n $goblin_old_node && ! -x $goblin_old_node ]]; then
    printf 'The installed service starts Node from %s, which no longer exists (was Node upgraded or moved?). It will use %s from now on.\n' "$goblin_old_node" "$goblin_node" >&2
  elif [[ -n $goblin_old_node && $goblin_old_node != "$goblin_node" ]]; then
    printf 'The service will start Node from %s instead of %s.\n' "$goblin_node" "$goblin_old_node"
  fi
fi
# Prepare the complete unit on its destination filesystem while the old service is still
# running. A full/read-only /etc must not interrupt a healthy installation. The private,
# unique directory also keeps partial output and stale temp files out of the active unit.
install -d -m 755 "$(dirname -- "$goblin_unit")"
goblin_unit_stage=$(mktemp -d "$(dirname -- "$goblin_unit")/.uptime-goblin-unit.XXXXXX")
# --supervised, as deploy/uptime-goblin.service gives it: /etc/uptime-goblin.env cannot turn it off. A rollback
# keeps this unit, so a release it restores is started with the argument too, but as Type=simple
# (rollback.service, below): an earlier release never reports ready to a Type=notify unit.
sed "s|^ExecStart=.*|ExecStart=$goblin_node /opt/uptime-goblin/server.mjs --supervised|" "$goblin_source/deploy/uptime-goblin.service" >"$goblin_unit_stage/uptime-goblin.service"
chmod 644 "$goblin_unit_stage/uptime-goblin.service"
sed -e 's|^Type=notify$|Type=simple|' -e '/^NotifyAccess=/d' -e '/^TimeoutStartSec=infinity$/d' "$goblin_unit_stage/uptime-goblin.service" >"$goblin_unit_stage/rollback.service"
chmod 644 "$goblin_unit_stage/rollback.service"
# What a rollback would restore, read now, before the stop (no signal can then cut these reads
# short): the copy in /opt/uptime-goblin, which the switch below moves to the rollback path unchanged, or
# else what that path already holds. The new copy's verifier reads its build. Releases before
# 1.4.3 have no process-nonce contract (goblin_legacy, used by the rollback below). With the Orbit
# layout, the copy in /opt/orbit, which the migration renames to /opt/uptime-goblin first.
goblin_rollback_source=$goblin_rollback
[[ -e $goblin_cur_app/server.mjs ]] && goblin_rollback_source=$goblin_cur_app
goblin_rollback_version=
goblin_rollback_build=
goblin_legacy=
if [[ -e $goblin_rollback_source/server.mjs ]]; then
  goblin_rollback_version=$("$goblin_node" -p 'require(process.argv[1]).version' "$goblin_rollback_source/package.json" 2>/dev/null || true)
  goblin_rollback_build=$("$goblin_node" "$goblin_stage/lib/healthcheck.mjs" --print-build "$goblin_rollback_source" 2>/dev/null || true)
  goblin_legacy=$("$goblin_node" -e 'const m=/^(\d+)\.(\d+)\.(\d+)(?:-|$)/.exec(process.argv[1]); if(m && +m[1]===1 && (+m[2]<4 || (+m[2]===4 && +m[3]<3)))process.stdout.write("1")' "$goblin_rollback_version")
fi
# From just before the stop until the new release is verified, or the previous one is restored
# and checked, a signal no longer ends the installer halfway (with the service stopped, the new
# copy unverified or /opt/uptime-goblin missing, and the EXIT trap removing the staged copy):
# - SIGHUP (the SSH session or terminal went away) is noted and the installer goes on; from then
#   on it writes its output to /run/uptime-goblin-install.log, since writing to a terminal that is gone
#   fails, and under set -e that would end it. A verifier that the hangup ended is started again.
# - SIGINT (Ctrl-C) and SIGTERM are noted and taken as a failed verification: the previous copy is
#   restored and started as after any failed start. One during the verifier's wait ends the wait at
#   once (the verifier runs in the background). One before the stop ends the installer there,
#   with the service running and its code unchanged.
# - The commands that stop, start and move run with all three signals ignored (goblin_shield), so
#   none of them is ended partway through.
# During the rollback the same holds, and a signal during its check ends that check.
goblin_interrupted=
goblin_signals=0
# The settings file the verifier reads HOST and PORT from (the Orbit one after a rollback that
# restored the Orbit layout).
goblin_verify_env=$goblin_env
goblin_hung_up=
goblin_on_signal() {
  if [[ $1 == HUP ]]; then
    if [[ -z $goblin_hung_up ]]; then
      goblin_hung_up=1
      exec >>"$goblin_root/run/uptime-goblin-install.log" 2>&1 </dev/null
      printf 'The installer received SIGHUP (its terminal went away) and goes on; its output follows.\n'
    fi
    return 0
  fi
  goblin_signals=$((goblin_signals + 1))
  if [[ -z $goblin_interrupted ]]; then
    goblin_interrupted=$1
    printf '\nThe installer received SIG%s. It finishes the step under way, then restores the previous version unless the new one is already verified.\n' "$1" >&2
  fi
  return 0
}
trap 'goblin_on_signal HUP' HUP
trap 'goblin_on_signal INT' INT
trap 'goblin_on_signal TERM' TERM
goblin_shield() { (trap '' HUP INT TERM; exec "$@"); }
# The verifier, in the background so that a signal ends the wait. It returns 1 when SIGINT or
# SIGTERM arrived during it (the verifier is then stopped), and is run again when it was ended by
# a signal (a hangup) and neither of those arrived.
goblin_verify() {
  local pid status tries=0 signals=$goblin_signals
  while :; do
    "$goblin_node" --env-file="$goblin_verify_env" "$@" &
    pid=$!
    status=0
    wait "$pid" || status=$?
    if ((goblin_signals != signals)); then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
      return 1
    fi
    # A trapped SIGHUP also ends the wait, with the verifier still running: wait for it again.
    while kill -0 "$pid" 2>/dev/null; do
      status=0
      wait "$pid" || status=$?
      if ((goblin_signals != signals)); then
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
        return 1
      fi
    done
    ((status > 128 && ++tries < 3)) || return "$status"
  done
}
printf 'Installing Uptime Goblin %s (build %s)…\n' "$goblin_version" "$goblin_build"
[[ -z $goblin_interrupted ]] || goblin_fail "The installer received SIG$goblin_interrupted before it stopped Uptime Goblin: the service and its code were not changed. Run this installer again."
# With the Orbit layout the migration takes the stop's place: it stops orbit.service and moves the
# layout (see the start). One that fails restores the Orbit layout and starts orbit.service again
# where it was running, and the upgrade stops there. From here on a failure, SIGINT or SIGTERM
# restores the Orbit layout with the previous release (goblin_migrated).
goblin_migrated=
if [[ $goblin_layout == orbit ]]; then
  goblin_status=0
  goblin_migration forward || goblin_status=$?
  if ((goblin_status != 0)); then
    goblin_status=0
    goblin_migration reverse recover || goblin_status=$?
    ((goblin_status != 0)) || goblin_fail 'Uptime Goblin was not installed, and the Orbit layout is as it was. Fix the problem above, then run this installer again.'
    ((goblin_status != 2)) || goblin_fail 'Uptime Goblin was not installed. The Orbit layout is as it was, but orbit.service could not be started again. Check: journalctl -u orbit.service'
    goblin_fail 'Uptime Goblin was not installed.'
  fi
  goblin_migrated=1
  goblin_layout=uptime-goblin
  goblin_key_messages
else
  [[ -f $goblin_unit ]] && { goblin_shield systemctl stop uptime-goblin.service || true; }
fi
if [[ -e $goblin_app/server.mjs ]]; then
  goblin_shield rm -rf -- "$goblin_rollback"
  goblin_shield mv -- "$goblin_app" "$goblin_rollback"
elif [[ -e $goblin_app ]]; then
  goblin_shield rm -rf -- "$goblin_app"
fi
goblin_shield mv -- "$goblin_stage" "$goblin_app"
goblin_can_roll_back=
[[ -e $goblin_rollback/server.mjs ]] && goblin_can_roll_back=1
goblin_started=1
# These commands run after the old service stopped and its code moved. Route any failure, and a
# SIGINT or SIGTERM, through the same rollback path as a failed start, rather than letting set -e
# leave it down.
if [[ -z $goblin_interrupted && ! -d $goblin_unit ]] && goblin_shield mv -- "$goblin_unit_stage/uptime-goblin.service" "$goblin_unit" &&
  goblin_unit_published=1 && goblin_shield systemctl daemon-reload && goblin_shield systemctl enable --quiet uptime-goblin.service &&
  [[ -z $goblin_interrupted ]]; then
  # --no-block: the Type=notify unit is active only once Uptime Goblin serves, and never times
  # out a slow start, so a blocking restart could wait for good; the verification below waits,
  # bounded by --verify-timeout. reset-failed first: a unit left failed by an earlier start would
  # otherwise read as this start's failure until the queued restart runs.
  goblin_shield systemctl reset-failed uptime-goblin.service >/dev/null 2>&1 || true
  goblin_shield systemctl restart --no-block uptime-goblin.service || goblin_started=
else
  goblin_started=
fi
printf 'Verifying that Uptime Goblin %s is serving (up to %s seconds)…\n' "$goblin_version" "$goblin_verify_timeout"
if [[ -n $goblin_started && -z $goblin_interrupted ]] && goblin_verify "$goblin_app/lib/healthcheck.mjs" --wait --timeout "$goblin_verify_timeout" --data-dir "$goblin_data" --expect-version "$goblin_version" --expect-build "$goblin_build" --unit uptime-goblin.service; then
  # Verified: the migration's record goes first, so that no later run undoes a migration that worked.
  [[ -z $goblin_migrated ]] || goblin_migration done
  printf 'Uptime Goblin %s is running and will start automatically after reboot.\n' "$goblin_version"
  if [[ -n $goblin_migrated ]]; then
    printf 'This installation now has the Uptime Goblin layout. The old settings file is kept as /etc/orbit.env.migrated, and the old unit file as /etc/systemd/system/orbit.service.migrated: remove them once Uptime Goblin works as it should. Scripts and webhook receivers that use the Orbit names keep working until 1.7 (docs/installation.md, "Renamed from Orbit").\n'
  fi
  [[ $goblin_rollback == "$goblin_reinstall" ]] && rm -rf -- "$goblin_reinstall"
  [[ -e $goblin_previous/server.mjs ]] && printf 'The previous version is kept in /opt/uptime-goblin.previous.\n'
  if [[ -n $goblin_installed_version ]] && goblin_before_15 "$goblin_installed_version" && ! goblin_before_15 "$goblin_version"; then
    # 1.5 replaces the browser's Basic prompt with a sign-in page and a session cookie.
    printf 'Sign in as admin with the same password. Reload Uptime Goblin tabs that were open before this upgrade once.\n'
    if [[ $goblin_key_file == "$goblin_shown_key_home/secret.key" ]]; then
      printf 'Encryption key: /etc/uptime-goblin/secret.key. Back it up separately from /var/lib/uptime-goblin.\n'
    fi
  else
    printf 'Open Uptime Goblin tabs now update themselves after an upgrade; tabs opened before 1.4.3 need one manual reload.\n'
  fi
  printf 'Settings: /etc/uptime-goblin.env\nData: /var/lib/uptime-goblin\nStatus: systemctl status uptime-goblin.service\n'
  exit 0
fi
if [[ -n $goblin_interrupted ]]; then
  printf '\nUptime Goblin %s was not verified: the installer received SIG%s. Service status and recent log:\n' "$goblin_version" "$goblin_interrupted" >&2
else
  printf '\nUptime Goblin %s did not start correctly. Service status and recent log:\n' "$goblin_version" >&2
fi
systemctl --no-pager --full status uptime-goblin.service >&2 || true
journalctl --unit=uptime-goblin.service --lines=50 --no-pager >&2 || true
# The status and the log are shown as they are, for the operator to read. The installer does not
# establish which start wrote a log line (an earlier start's lines can be among them), so it draws
# no diagnosis from them and recommends no setting (maintainer disposition of review F-02-R2). A start
# refused for want of a resource limit says why in its own lines, and Resource limits in
# docs/installation.md says what to do.
# A migrated host gets the Orbit layout back, as it was (goblin_migration reverse): with no
# previous version too, which leaves the new release in /opt/uptime-goblin.failed.
goblin_restore_layout() {
  goblin_status=0
  goblin_migration reverse rollback || goblin_status=$?
  ((goblin_status != 1)) || goblin_fail 'The Orbit layout could not be restored (above). Run this installer again: it goes on restoring the Orbit layout before anything else.'
}
if [[ -z $goblin_can_roll_back ]]; then
  if [[ -n $goblin_migrated ]]; then
    goblin_shield systemctl stop uptime-goblin.service || true
    goblin_restore_layout
    goblin_fail "There is no previous version to restore; the Orbit layout is as it was, and this release is kept in /opt/uptime-goblin.failed. Fix the problem above, then run the installer again."
  fi
  goblin_fail "There is no previous version to restore. Fix the problem above, then run the installer again."
fi
# An earlier 1.5 pre-release build signs webhooks with an HMAC secret, kept in a settings field
# that it opens without checking what it holds, and shows it under Show signing secret. This
# release keeps the webhook's Ed25519 private keys in other fields, and its start, with or without
# a webhook, saves those settings in a form such a build can read but not change, with a key that
# a 1.5 build before this release kept in that field moved out of it (by its webhook signing code):
# started on that data, such a build sends webhooks unsigned and shows no signing secret. But the
# failed start may have stopped before that, and a key still in that field is the earlier build's
# to take for its secret, sign with and show, at once with GOBLIN_WEBHOOK_URL set or once it is set
# later: a key stays in the data without a webhook. Which of these holds cannot be told without
# opening the sealed settings, so GOBLIN_WEBHOOK_URL decides nothing here: a release to restore that
# is, or cannot be told apart from, such a build is neither restored nor started. The service is
# stopped, /opt/uptime-goblin keeps this release (a reboot starts it, never the earlier build), the earlier
# build stays where it is, and the installer says how to go on. Such a build: a 1.5 version with a
# pre-release part (1.5.0-dev.1), or a version that cannot be read, whose lib/ does not declare
# this release's public-key route ('/api/notifications/webhook/public-key') or still holds the
# earlier builds' reveal route (/api/notifications/webhook/signing-secret/reveal). The check only
# reads the copy to restore; the service is stopped once it refuses.
if ! "$goblin_node" - "$goblin_rollback" "$goblin_rollback_version" "$goblin_version" "${goblin_rollback#"$goblin_root"}" <<'NODE'
const fs=require('node:fs'),path=require('node:path');
const [tree,version,current,shown]=process.argv.slice(2);
const release=/^(\d+)\.(\d+)\.(\d+)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$/.exec(version);
// 1.4.x keeps no signing key, and 1.5.0 and later sign with this release's key pair.
if(release&&!(+release[1]===1&&+release[2]===5&&release[4]))process.exit(0);
let publicKey=false,reveal=false,files=0;
try{
  const walk=dir=>{
    for(const entry of fs.readdirSync(dir,{withFileTypes:true})){
      const at=path.join(dir,entry.name);
      if(entry.isDirectory())walk(at);
      else if(entry.isFile()&&/\.m?js$/.test(entry.name)){
        if(++files>2000)throw new Error('too many files');
        const text=fs.readFileSync(at,'latin1');
        publicKey||=text.includes("'/api/notifications/webhook/public-key'");
        reveal||=text.includes('/api/notifications/webhook/signing-secret/reveal');
      }
    }
  };
  walk(path.join(tree,'lib'));
}catch{publicKey=false;}
if(publicKey&&!reveal)process.exit(0);
const which=release?`, Uptime Goblin ${version}, is an earlier 1.5 pre-release build that signs webhooks with an HMAC secret (or cannot be told apart from one by its files)`:` (whose version is not one this installer can read) cannot be told apart from an earlier 1.5 pre-release build that signs webhooks with an HMAC secret`;
console.error(`\nThe upgrade to ${current} was not rolled back: the previous version in ${shown}${which}. Uptime Goblin ${current} keeps the webhook's private signing keys where such a build cannot read them, so on data that Uptime Goblin ${current} has run on such a build shows no signing secret and sends webhooks unsigned; but a private key that a 1.5 build from before Uptime Goblin ${current} kept in the field of that HMAC secret leaves it only at a start of Uptime Goblin ${current} that gets that far, and such a build takes a key still there for its secret: it signs with the key's text and shows it under Show signing secret, also once GOBLIN_WEBHOOK_URL is set later. The service is stopped, and /opt/uptime-goblin still holds Uptime Goblin ${current}. Fix the problem above, then run the installer again. To go back to the earlier build instead, first restore Uptime Goblin's data from before this upgrade (a snapshot or a backup), then swap the two copies, make the unit Type=simple (such a build never reports ready to this release's Type=notify unit, so a start would wait for good; the next upgrade writes Type=notify again) and start it: sudo mv /opt/uptime-goblin /opt/uptime-goblin.${current} && sudo mv ${shown} /opt/uptime-goblin && sudo mv /opt/uptime-goblin.${current} ${shown} && sudo sed -i -e 's/^Type=notify$/Type=simple/' /etc/systemd/system/uptime-goblin.service && sudo systemctl daemon-reload && sudo systemctl start uptime-goblin.service. Data from before this upgrade can hold such a key too. If an earlier build that signs with an HMAC secret runs, or ran before this upgrade, on data that a 1.5 build from before Uptime Goblin ${current} that signs with Ed25519 ran on (this data or data from before this upgrade alike), press Replace signing key twice once Uptime Goblin ${current} runs again (with GOBLIN_WEBHOOK_URL set), and give receivers the new public key.`);
process.exit(1);
NODE
then
  goblin_shield systemctl stop uptime-goblin.service || true
  # Neither restored nor started: the Uptime Goblin layout stays, with this release, which is what
  # a reboot starts. The migration is finished as it is, so no later run undoes it.
  [[ -z $goblin_migrated ]] || goblin_migration done
  exit 1
fi
goblin_rb_app=$goblin_app goblin_rb_data=$goblin_data goblin_rb_service=uptime-goblin.service
if [[ -n $goblin_migrated ]]; then
  # The previous release goes back to /opt/orbit with the rest of the Orbit layout, and starts as
  # orbit.service again; this release is kept in /opt/uptime-goblin.failed.
  printf '\nRestoring the previous version from %s and the Orbit layout…\n' "${goblin_rollback#"$goblin_root"}" >&2
  goblin_restore_layout
  ((goblin_status != 2)) || goblin_fail 'The previous code and the Orbit layout were restored, but orbit.service could not be restarted. Check: journalctl -u orbit.service'
  goblin_rb_app=$legacy_app goblin_rb_data=$legacy_data goblin_rb_service=orbit.service goblin_verify_env=$legacy_env
else
  printf '\nRestoring the previous version from %s…\n' "${goblin_rollback#"$goblin_root"}" >&2
  goblin_shield systemctl stop uptime-goblin.service || true
  goblin_shield rm -rf -- "$goblin_failed"
  goblin_shield mv -- "$goblin_app" "$goblin_failed"
  goblin_shield mv -- "$goblin_rollback" "$goblin_app"
  # This release's unit as Type=simple: it is Type=notify, and an earlier release that never
  # reports ready would stay activating under it. Limits, sandbox and --supervised stay. Only
  # when this release's unit was published: otherwise the old unit is still the one on disk.
  if [[ -n $goblin_unit_published && -f $goblin_unit_stage/rollback.service ]] && ! goblin_shield mv -- "$goblin_unit_stage/rollback.service" "$goblin_unit"; then
    printf 'WARNING: the unit could not be made Type=simple for the restored release; it may stay activating although it serves.\n' >&2
  fi
  if ! goblin_shield systemctl daemon-reload; then
    printf 'WARNING: systemd could not reload its unit files during rollback; trying the already loaded unit.\n' >&2
  fi
  goblin_shield systemctl reset-failed uptime-goblin.service >/dev/null 2>&1 || true
  if ! goblin_shield systemctl restart --no-block uptime-goblin.service; then
    goblin_fail 'The previous code was restored, but its service could not be restarted. Check: journalctl -u uptime-goblin.service'
  fi
fi
# Releases before 1.4.3 have no process-nonce contract (goblin_legacy, worked out before the stop).
# Their old health check can answer for another process on the port, so report its limited
# result without claiming verified recovery.
if [[ -n $goblin_legacy ]]; then
  # Old probes have only a socket-idle timeout: trickling responses can keep them alive.
  # Bound the whole probe process without relying on a timeout command being installed.
  if "$goblin_node" - "$goblin_verify_timeout" "$goblin_verify_env" "$goblin_rb_app/lib/healthcheck.mjs" <<'NODE'
const {spawnSync}=require('node:child_process');
const seconds=Number(process.argv[2]);
const result=spawnSync(process.execPath,[`--env-file=${process.argv[3]}`,process.argv[4],'--wait'],{stdio:'inherit',timeout:seconds*1000,killSignal:'SIGKILL'});
if(result.error?.code==='ETIMEDOUT')console.error(`Legacy health check exceeded its ${seconds} second verification deadline.`);
process.exitCode=result.status===0&&!result.error?0:1;
NODE
  then
    goblin_fail 'The previous code was restored and its legacy health check answered. Its process identity is unverified; confirm the service status and logs before relying on it.'
  fi
  goblin_fail "The previous code was restored, but its legacy health check did not pass. Check: journalctl -u $goblin_rb_service"
fi
# Use the new verifier even when the restored release has an older healthcheck implementation.
goblin_rollback_signals=$goblin_signals
if goblin_verify "$goblin_failed/lib/healthcheck.mjs" --wait --timeout "$goblin_verify_timeout" --data-dir "$goblin_rb_data" --expect-version "$goblin_rollback_version" --expect-build "$goblin_rollback_build" --unit "$goblin_rb_service"; then
  goblin_fail "The previous version is running again; the upgrade to $goblin_version was rolled back.${goblin_migrated:+ The Orbit layout is restored as it was, and orbit.service runs it.} Its files are kept in /opt/uptime-goblin.failed for diagnosis."
fi
if ((goblin_signals != goblin_rollback_signals)); then
  goblin_fail "The previous code was restored and its service restarted, but a signal ended the check that it serves. Check: systemctl status $goblin_rb_service and journalctl -u $goblin_rb_service"
fi
goblin_fail "The previous version could not be verified after restoring its code. Check: journalctl -u $goblin_rb_service"
