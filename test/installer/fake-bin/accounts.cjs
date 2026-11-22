// Installer tests run unprivileged: a model of the account database for the account tools the
// installer runs (id, getent, groupadd, useradd, usermod, groupmod), kept in
// $FAKE_SYSTEMD_DIR/accounts.json ({users: {name: {uid, gid, home}}, groups: {name: gid}}; none
// until a tool adds one, or a test writes the file). `id -u` reports root. Each call that changes
// the database is noted in $FAKE_SYSTEMD_DIR/accounts.log.
'use strict';
const fs = require('node:fs');
const path = require('node:path');

const [tool, ...args] = process.argv.slice(2);
const file = path.join(process.env.FAKE_SYSTEMD_DIR, 'accounts.json');
let db = { users: {}, groups: {} };
try {
  db = JSON.parse(fs.readFileSync(file, 'utf8'));
} catch (error) {
  if (error.code !== 'ENOENT') throw error;
}
const save = () => {
  fs.writeFileSync(`${file}.tmp`, JSON.stringify(db));
  fs.renameSync(`${file}.tmp`, file);
  fs.appendFileSync(
    path.join(process.env.FAKE_SYSTEMD_DIR, 'accounts.log'),
    `${tool} ${args.join(' ')}\n`
  );
};
const option = name => {
  const at = args.indexOf(name);
  return at < 0 ? undefined : args[at + 1];
};
const fail = (status, message) => {
  console.error(`${tool}: ${message}`);
  process.exit(status);
};
const next = used => Math.max(998, ...used) + 1;
const name = args.at(-1);
switch (tool) {
  case 'id':
    if (args[0] === '-u' && args.length === 1) {
      console.log(0);
      break;
    }
    if (!db.users[name]) fail(1, `'${name}': no such user`);
    console.log(
      `uid=${db.users[name].uid}(${name}) gid=${db.users[name].gid}(${name}) groups=${db.users[name].gid}(${name})`
    );
    break;
  case 'getent':
    if (args[0] === 'passwd' && db.users[name]) {
      const user = db.users[name];
      console.log(`${name}:x:${user.uid}:${user.gid}::${user.home}:/usr/sbin/nologin`);
    } else if (args[0] === 'group' && db.groups[name] !== undefined)
      console.log(`${name}:x:${db.groups[name]}:`);
    else process.exit(2);
    break;
  case 'groupadd':
    if (db.groups[name] !== undefined) fail(9, `group '${name}' already exists`);
    db.groups[name] = next(Object.values(db.groups));
    save();
    break;
  case 'useradd': {
    if (db.users[name]) fail(9, `user '${name}' already exists`);
    const group = option('--gid');
    if (group !== undefined && db.groups[group] === undefined)
      fail(6, `group '${group}' does not exist`);
    db.users[name] = {
      uid: next(Object.values(db.users).map(user => user.uid)),
      gid: db.groups[group],
      home: option('--home'),
    };
    save();
    break;
  }
  case 'usermod': {
    const to = option('-l');
    if (!db.users[name]) fail(6, `user '${name}' does not exist`);
    if (to && db.users[to]) fail(9, `user '${to}' already exists`);
    const user = db.users[name];
    if (option('-d') !== undefined) user.home = option('-d');
    if (to) {
      delete db.users[name];
      db.users[to] = user;
    }
    save();
    break;
  }
  case 'groupmod': {
    const to = option('-n');
    if (db.groups[name] === undefined) fail(6, `group '${name}' does not exist`);
    if (db.groups[to] !== undefined) fail(9, `group '${to}' already exists`);
    db.groups[to] = db.groups[name];
    delete db.groups[name];
    save();
    break;
  }
  default:
    fail(64, 'not modelled');
}
