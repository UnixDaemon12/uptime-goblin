import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { inspect } from 'node:util';
import { ConfigStore, InputError, checkConfigFile } from '../lib/config.mjs';
import { newService } from '../lib/catalog.mjs';

function temporary(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-config-hardening-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

for (const linked of [false, true])
  test(`configuration startup refuses a ${linked ? 'symlinked ' : ''}FIFO without waiting for a writer`, t => {
    const directory = temporary(t),
      file = path.join(directory, 'config.json'),
      fifo = linked ? path.join(directory, 'pipe') : file;
    assert.equal(spawnSync('mkfifo', [fifo]).status, 0);
    if (linked) fs.symlinkSync(fifo, file);
    // In a child with a deadline: a blocking open would hang this process for good. Both
    // readers of the start: the read-only check and the store.
    const child = spawnSync(
      process.execPath,
      [
        '--input-type=module',
        '-e',
        `import assert from 'node:assert/strict';
         import { ConfigStore, checkConfigFile } from ${JSON.stringify(new URL('../lib/config.mjs', import.meta.url).href)};
         const refused = error => error.refusal === true && /regular file/.test(error.message);
         assert.throws(() => checkConfigFile(process.argv[1]), refused);
         assert.throws(() => new ConfigStore(process.argv[1]), refused);`,
        directory,
      ],
      { encoding: 'utf8', timeout: 3000, killSignal: 'SIGKILL' }
    );
    assert.equal(child.error, undefined, 'startup must return before the child deadline');
    assert.equal(child.status, 0, child.stderr);
    assert.ok(fs.statSync(fifo).isFIFO(), 'the refusal leaves the entry as it was');
  });

test('configuration startup refuses files over 128 MiB before reading their contents', t => {
  const directory = temporary(t),
    file = path.join(directory, 'config.json'),
    descriptor = fs.openSync(file, 'wx', 0o600);
  fs.ftruncateSync(descriptor, 128 * 1024 * 1024 + 1);
  fs.closeSync(descriptor);
  const read = t.mock.method(fs, 'readSync', () => {
    assert.fail('an oversized configuration must be refused before its contents are read');
  });
  for (const start of [() => checkConfigFile(directory), () => new ConfigStore(directory)])
    assert.throws(start, error => error.refusal === true && /128 MiB/.test(error.message));
  assert.equal(read.mock.callCount(), 0);
});

test('configuration startup reads no further than it checked when the file grows after inspection', t => {
  const directory = temporary(t),
    config = new ConfigStore(directory),
    stat = fs.fstatSync;
  let inspected;
  t.mock.method(fs, 'fstatSync', (descriptor, ...rest) => {
    const result = stat(descriptor, ...rest);
    inspected = descriptor;
    fs.appendFileSync(config.file, ' '.repeat(1024));
    return result;
  });
  assert.throws(
    () => new ConfigStore(directory),
    error => error.refusal === true && /changed while it was read/.test(error.message)
  );
  assert.ok(inspected !== undefined);
  assert.throws(() => stat(inspected), { code: 'EBADF' }, 'the refused descriptor is closed');
});

test('a large older configuration with 200 sources still loads through a regular-file symlink', t => {
  const directory = temporary(t),
    file = path.join(directory, 'saved.json'),
    services = Array.from({ length: 200 }, (_, i) => ({
      ...newService('http', `http-${i + 1}`),
      password: 'synthetic-legacy-credential-'.repeat(200),
      apiKey: 'synthetic-legacy-key-'.repeat(200),
    })),
    contents = JSON.stringify({ services }, null, 2);
  assert.ok(Buffer.byteLength(contents) > 150000, 'saved configurations exceed one request body');
  fs.writeFileSync(file, contents);
  fs.symlinkSync(file, path.join(directory, 'config.json'));
  assert.equal(checkConfigFile(directory), true);
  const config = new ConfigStore(directory);
  assert.equal(config.value.services.length, 200);
  assert.equal(config.value.services[199].password, services[199].password);
  assert.equal(fs.readFileSync(file, 'utf8'), contents);
});

test('an unsupported saved source type never appears in startup diagnostics or nested causes', t => {
  const directory = temporary(t),
    canary = 'SYNTHETIC_UNSUPPORTED_TYPE_CANARY';
  fs.writeFileSync(
    path.join(directory, 'config.json'),
    JSON.stringify({ services: [{ ...newService('http', 'http-1'), type: canary }] })
  );
  for (const start of [() => checkConfigFile(directory), () => new ConfigStore(directory)])
    assert.throws(start, error => {
      assert.equal(error.refusal, true);
      assert.equal(inspect(error, { depth: 10 }).includes(canary), false);
      assert.equal(inspect(error, { depth: 10 }).includes(canary.slice(0, 12)), false);
      assert.match(
        error.message,
        /source http-1 has a type this version of Uptime Goblin does not support/
      );
      return true;
    });
});

test('saved single-line texts with control or text-direction characters are repaired on start, never logged', t => {
  const directory = temporary(t),
    canary = 'CANARY';
  const saved = {
    title: `Home\u202e${canary}`,
    subtitle: `a\nb`,
    services: [
      {
        ...newService('json', 'json-1'),
        name: `line1\nline2\u2066${canary}`,
        group: `G\u0007`,
        username: `user\t${canary}`,
        metrics: [
          {
            key: 'm',
            path: 'p',
            label: `L\u202a${canary}`,
            unit: `u\r`,
            // Label filters must equal the exporter's values, so they are kept as saved.
            labels: { job: `j\u2028`, note: 'line1\nline2', dir: '\u202bvol\u202c' },
          },
        ],
      },
      // Nothing but direction controls: the name falls back to the type's default.
      { ...newService('link', 'link-1'), name: '\u202e\u202c' },
      { ...newService('unifi', 'unifi-1'), siteId: `default\u202e` },
    ],
  };
  fs.writeFileSync(path.join(directory, 'config.json'), JSON.stringify(saved));
  const warnings = [];
  t.mock.method(console, 'warn', (...args) => warnings.push(args.join(' ')));
  const config = new ConfigStore(directory);
  assert.equal(config.value.title, `Home${canary}`);
  assert.equal(config.value.subtitle, 'a b');
  const [json, link, unifi] = config.value.services;
  assert.equal(json.name, `line1 line2${canary}`);
  assert.equal(json.group, 'G');
  assert.equal(json.username, `user ${canary}`);
  assert.deepEqual([json.metrics[0].label, json.metrics[0].unit], [`L${canary}`, 'u']);
  assert.deepEqual(json.metrics[0].labels, saved.services[0].metrics[0].labels);
  assert.equal(link.name, newService('link').name);
  assert.equal(unifi.siteId, 'default');
  assert.equal(config.repaired, true);
  // Saved once, so a restart repairs nothing again; the warnings name fields, never values.
  assert.ok(warnings.length >= 9, warnings.join('\n'));
  for (const line of warnings) {
    assert.doesNotMatch(line, new RegExp(canary));
    assert.doesNotMatch(line, /[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/);
  }
  assert.ok(warnings.some(line => /name of source 1/.test(line)));
  assert.ok(!warnings.some(line => /label value/.test(line)), warnings.join('\n'));
  warnings.length = 0;
  assert.equal(new ConfigStore(directory).repaired, false);
  assert.deepEqual(warnings, []);
});

test('saved text holding half a surrogate pair is made whole on start, named by place only', t => {
  const directory = temporary(t),
    file = path.join(directory, 'config.json'),
    half = '\ud83d',
    canary = 'CANARY';
  const saved = {
    title: `Home ${half}${canary}`,
    services: [
      {
        ...newService('json', 'json-1'),
        name: `Server${half}`,
        password: `secret${half}${canary}`,
        rules: [{ key: `disk_${half}`, operator: 'gt', threshold: 90 }],
        metrics: [{ key: 'm', path: 'p', label: `L${half}`, labels: { job: `j${half}` } }],
      },
    ],
  };
  // Written as 1.4.3 writes it: JSON.stringify keeps half a pair as a \u escape.
  const lone = /\\ud[89a-f][0-9a-f]{2}/i;
  fs.writeFileSync(file, JSON.stringify(saved));
  assert.match(fs.readFileSync(file, 'utf8'), lone);
  const warnings = [];
  t.mock.method(console, 'warn', (...args) => warnings.push(args.join(' ')));
  const config = new ConfigStore(directory);
  const [json] = config.value.services;
  assert.equal(config.value.title, `Home �${canary}`);
  assert.equal(json.name, 'Server�');
  assert.equal(json.password, `secret�${canary}`);
  assert.equal(json.rules[0].key, 'disk_�');
  assert.equal(json.metrics[0].label, 'L�');
  assert.deepEqual(json.metrics[0].labels, { job: 'j�' });
  // JSON.stringify writes half a pair as an escape: none is left, in memory or in the file.
  assert.doesNotMatch(JSON.stringify(config.value), lone);
  assert.doesNotMatch(fs.readFileSync(file, 'utf8'), lone);
  assert.equal(config.repaired, true);
  // Each one named by its place, never by its text (a password among them).
  const named = warnings.filter(line => /surrogate/.test(line));
  assert.deepEqual(
    named.map(line => line.match(/^Configuration: (\S+) "\(hidden\)"/)?.[1]).sort(),
    [
      'services[0].metrics[0].label',
      'services[0].metrics[0].labels.job',
      'services[0].name',
      'services[0].password',
      'services[0].rules[0].key',
      'title',
    ]
  );
  // The label filter is one of them: which half it held is lost, and the log says what that
  // means for its reading, once (see mappedSamples() in lib/collectors.mjs).
  const matchers = warnings.filter(line => / mapping label filter/.test(line));
  assert.deepEqual(matchers, [
    "Configuration: 1 of these texts is a mapping label filter or path. Which half such a filter or path held is lost: when nothing matches it as the source sends it, it is compared with the source's text with any half read as U+FFFD. It reads as before while the source sends neither U+FFFD itself nor another half there; with U+FFFD there, that series or member is read instead, and with two different halves, nothing (the source shows a note).",
  ]);
  for (const line of warnings) {
    assert.doesNotMatch(line, new RegExp(`${canary}|secret|disk_|Server`));
    assert.equal(line.isWellFormed(), true);
  }
  warnings.length = 0;
  assert.equal(new ConfigStore(directory).repaired, false);
  assert.deepEqual(warnings, []);

  // Ten places are named at most; the rest are counted.
  const many = temporary(t);
  const rules = Array.from({ length: 13 }, (_, i) => ({
    key: `k${i}${half}`,
    operator: 'gt',
    threshold: 1,
  }));
  fs.writeFileSync(
    path.join(many, 'config.json'),
    JSON.stringify({ services: [{ ...newService('linux', 'linux-1'), rules }] })
  );
  const loaded = new ConfigStore(many);
  assert.deepEqual(
    loaded.value.services[0].rules.map(r => r.key),
    rules.map((_, i) => `k${i}�`)
  );
  assert.equal(warnings.filter(line => /\(hidden\)/.test(line)).length, 10);
  assert.ok(
    warnings.includes(
      'Configuration: 3 more texts holding half a surrogate pair were made whole the same way.'
    ),
    warnings.join('\n')
  );
  // Rule keys only: no mapping label filter or path, so no word on mapping readings.
  assert.ok(!warnings.some(line => /mapping label filter/.test(line)), warnings.join('\n'));

  // Counted past the ten places named: twelve rule keys first, then a label filter and a path.
  warnings.length = 0;
  const mixed = temporary(t);
  fs.writeFileSync(
    path.join(mixed, 'config.json'),
    JSON.stringify({
      services: [
        { ...newService('linux', 'linux-1'), rules: rules.slice(0, 12) },
        {
          ...newService('json', 'json-1'),
          metrics: [{ key: 'm', label: 'M', path: `a.b${half}` }],
        },
        {
          ...newService('prometheus', 'prometheus-1'),
          metrics: [{ key: 'm', label: 'M', path: 'up', labels: { ['l'.repeat(65)]: half } }],
        },
      ],
    })
  );
  new ConfigStore(mixed);
  assert.equal(warnings.filter(line => /\(hidden\)/.test(line)).length, 10);
  assert.deepEqual(
    warnings.filter(line => /mapping label filter/.test(line)).map(line => line.slice(0, 80)),
    ['Configuration: 2 of these texts are mapping label filters or paths. Which half s']
  );
});

test('rule keys that differ only in half a surrogate pair keep the first rule instead of refusing the start', t => {
  // 1.4.3 loaded these: two keys as saved. Made whole, they are one key, which validation
  // refuses ("Only one rule per measurement"), so the start was refused.
  const rule = (key, threshold) => ({ key, operator: 'gt', threshold, forSeconds: 60 });
  const write = (directory, rules) =>
    fs.writeFileSync(
      path.join(directory, 'config.json'),
      JSON.stringify({
        services: [
          { ...newService('linux', 'linux-1'), rules: [rule('cpu', 1)] },
          { ...newService('linux', 'linux-2'), rules },
        ],
      })
    );
  const warnings = [];
  t.mock.method(console, 'warn', (...args) => warnings.push(args.join(' ')));
  const directory = temporary(t);
  write(directory, [
    rule('disk_x\ud800', 1),
    rule('memory', 2),
    rule('disk_x\udbff', 3),
    rule('disk_x\ufffd', 4),
  ]);
  const config = new ConfigStore(directory);
  assert.deepEqual(
    config.value.services[1].rules.map(r => [r.key, r.threshold]),
    [
      ['disk_x\ufffd', 1],
      ['memory', 2],
    ]
  );
  assert.equal(config.repaired, true);
  // Named by place, never by text.
  assert.deepEqual(
    warnings.filter(line => /was removed/.test(line)),
    [3, 4].map(
      n =>
        `Configuration: alert rule ${n} of source 2 was removed: made whole, its measurement key is that of rule 1, and a measurement takes one rule.`
    )
  );
  for (const line of warnings) assert.doesNotMatch(line, /disk_/);
  // Saved once: the next start finds nothing to repair.
  warnings.length = 0;
  assert.equal(new ConfigStore(directory).repaired, false);
  assert.deepEqual(warnings, []);
  // A key saved twice as the same text is refused, as 1.4.3 refused it, also beside a removal.
  for (const rules of [
    [rule('disk', 1), rule('disk', 2)],
    [rule('disk_x\ud800', 1), rule('disk_x\udbff', 2), rule('disk_x\udbff', 3)],
  ]) {
    const refused = temporary(t);
    write(refused, rules);
    assert.throws(() => new ConfigStore(refused), /Only one rule per measurement/);
  }
});

for (const kind of ['file', 'symlink'])
  test(`a configuration save preserves an unowned temporary ${kind} on exclusive-create collision`, t => {
    const directory = temporary(t),
      config = new ConfigStore(path.join(directory, 'data')),
      before = config.value,
      saved = fs.readFileSync(config.file, 'utf8'),
      unrelated = path.join(directory, 'unrelated.txt'),
      contents = 'Keep these unrelated bytes';
    fs.writeFileSync(unrelated, contents, { mode: 0o640 });
    const open = fs.openSync;
    let collision, inode, permissions;
    t.mock.method(fs, 'openSync', (file, flags, mode) => {
      if (!collision && typeof file === 'string' && file.startsWith(config.file + '.')) {
        collision = file;
        // Occupy the actual randomly named path immediately before Uptime Goblin opens it.
        // This exercises exclusive create, unlike an old fixed-name .tmp fixture.
        if (kind === 'symlink') fs.symlinkSync(unrelated, collision);
        else {
          const descriptor = open(collision, 'wx', 0o640);
          fs.writeFileSync(descriptor, contents);
          fs.closeSync(descriptor);
        }
        inode = fs.lstatSync(collision).ino;
        permissions = fs.statSync(collision).mode & 0o777;
      }
      return open(file, flags, mode);
    });

    assert.throws(() => config.updateGlobal({ title: 'Must not be published' }), {
      code: 'EEXIST',
    });
    assert.ok(collision, 'the collision occurs at the path this save actually opens');
    assert.equal(fs.lstatSync(collision).ino, inode, 'cleanup must not remove an unowned entry');
    assert.equal(fs.lstatSync(collision).isSymbolicLink(), kind === 'symlink');
    assert.equal(fs.readFileSync(collision, 'utf8'), contents, 'the collision is never truncated');
    assert.equal(fs.readFileSync(unrelated, 'utf8'), contents, 'a symlink target is never written');
    assert.equal(fs.statSync(collision).mode & 0o777, permissions);
    assert.equal(config.value, before, 'a failed save does not publish its candidate in memory');
    assert.equal(fs.readFileSync(config.file, 'utf8'), saved);
  });

for (const stage of ['partial write', 'fsync'])
  test(`a configuration save removes its owned temporary file after ${stage} failure`, t => {
    const directory = temporary(t),
      config = new ConfigStore(directory),
      before = config.value,
      saved = fs.readFileSync(config.file, 'utf8'),
      open = fs.openSync,
      write = fs.writeFileSync;
    let temporaryFile, descriptor;
    t.mock.method(fs, 'openSync', (file, flags, mode) => {
      const result = open(file, flags, mode);
      if (typeof file === 'string' && file.startsWith(config.file + '.')) {
        temporaryFile = file;
        descriptor = result;
      }
      return result;
    });
    if (stage === 'partial write')
      t.mock.method(fs, 'writeFileSync', (file, contents, ...args) => {
        if (file !== descriptor) return write(file, contents, ...args);
        fs.writeSync(file, String(contents).slice(0, 80));
        throw Object.assign(new Error('fixture partial write'), { code: 'ENOSPC' });
      });
    else
      t.mock.method(fs, 'fsyncSync', () => {
        throw Object.assign(new Error('fixture fsync failure'), { code: 'EIO' });
      });
    assert.throws(() => config.updateGlobal({ title: 'Fixture secret in an unsaved candidate' }), {
      code: stage === 'partial write' ? 'ENOSPC' : 'EIO',
    });
    assert.ok(temporaryFile);
    assert.deepEqual(fs.readdirSync(directory), ['config.json']);
    assert.throws(() => fs.fstatSync(descriptor), { code: 'EBADF' });
    assert.equal(config.value, before);
    assert.equal(fs.readFileSync(config.file, 'utf8'), saved);
  });

test('a configuration save never closes a descriptor reused after a close error', t => {
  const directory = temporary(t),
    config = new ConfigStore(path.join(directory, 'data')),
    before = config.value,
    saved = fs.readFileSync(config.file, 'utf8'),
    unrelated = path.join(directory, 'unrelated.txt'),
    contents = 'An unrelated open file';
  fs.writeFileSync(unrelated, contents);
  const open = fs.openSync,
    close = fs.closeSync;
  let savingDescriptor, replacement;
  t.after(() => {
    if (replacement !== undefined)
      try {
        close(replacement);
      } catch {}
  });
  t.mock.method(fs, 'openSync', (file, flags, mode) => {
    const descriptor = open(file, flags, mode);
    if (typeof file === 'string' && file.startsWith(config.file + '.'))
      savingDescriptor = descriptor;
    return descriptor;
  });
  t.mock.method(fs, 'closeSync', descriptor => {
    if (descriptor === savingDescriptor && replacement === undefined) {
      close(descriptor);
      replacement = open(unrelated, 'r');
      assert.equal(replacement, descriptor, 'the fixture reuses the released descriptor');
      throw Object.assign(new Error('fixture close failure'), { code: 'EIO' });
    }
    return close(descriptor);
  });
  assert.throws(() => config.updateGlobal({ title: 'Must not be published' }), { code: 'EIO' });
  assert.ok(replacement !== undefined);
  assert.equal(fs.readFileSync(replacement, 'utf8'), contents, 'the replacement must remain open');
  assert.deepEqual(fs.readdirSync(path.dirname(config.file)), ['config.json']);
  assert.equal(config.value, before);
  assert.equal(fs.readFileSync(config.file, 'utf8'), saved);
});

test('invalid configuration JSON never places its contents in the startup error or cause', t => {
  const directory = temporary(t);
  for (const contents of ['{"password": BADSECRET}', 'BADSECRET']) {
    fs.writeFileSync(path.join(directory, 'config.json'), contents);
    assert.throws(
      () => new ConfigStore(directory),
      error => {
        assert.equal(error.refusal, true);
        assert.equal(error.cause.message, 'Expected valid JSON');
        assert.ok(error.cause instanceof InputError);
        assert.equal(error.cause.cause, undefined);
        assert.ok(!inspect(error, { depth: 10 }).includes('BADSECRET'));
        return true;
      }
    );
  }
});

test('invalid configuration JSON retains a numeric line and column without retaining its contents', t => {
  const directory = temporary(t);
  fs.writeFileSync(
    path.join(directory, 'config.json'),
    '{\n  "password": "BADSECRET"\n  "services": []\n}'
  );
  assert.throws(
    () => new ConfigStore(directory),
    error => {
      assert.equal(error.refusal, true);
      assert.match(error.message, /Expected valid JSON at line 3, column 3/);
      assert.ok(error.cause instanceof InputError);
      assert.equal(error.cause.message, 'Expected valid JSON at line 3, column 3');
      assert.equal(error.cause.line, 3);
      assert.equal(error.cause.column, 3);
      assert.equal(error.cause.position, 30);
      assert.equal(error.cause.cause, undefined);
      assert.ok(!inspect(error, { depth: 10 }).includes('BADSECRET'));
      return true;
    }
  );
});

test('JSON diagnostics accept numeric locations only and keep unsupported error formats generic', t => {
  const directory = temporary(t),
    contents = '{"password": BADSECRET}',
    parse = JSON.parse;
  fs.writeFileSync(path.join(directory, 'config.json'), contents);
  let diagnostic;
  t.mock.method(JSON, 'parse', (text, ...args) => {
    if (text === contents) throw new SyntaxError(diagnostic);
    return parse(text, ...args);
  });
  for (const [message, expected, location] of [
    ['BADSECRET at position 13', 'Expected valid JSON at position 13', { position: 13 }],
    [
      'BADSECRET (line 2 column 4)',
      'Expected valid JSON at line 2, column 4',
      { line: 2, column: 4 },
    ],
    ['Unexpected token B, "BADSECRET at position 13" is not valid JSON', 'Expected valid JSON', {}],
    ['Unexpected token x, "x (line 42 column 7)" is not valid JSON', 'Expected valid JSON', {}],
    ['BADSECRET at position 9007199254740992', 'Expected valid JSON', {}],
    ['BADSECRET (line 9007199254740992 column 7)', 'Expected valid JSON', {}],
    ['BADSECRET (line 42 column 9007199254740992)', 'Expected valid JSON', {}],
    ['BADSECRET (line 0 column 4)', 'Expected valid JSON', {}],
    ['BADSECRET at position -1', 'Expected valid JSON', {}],
  ]) {
    diagnostic = message;
    assert.throws(
      () => new ConfigStore(directory),
      error => {
        assert.equal(error.cause.message, expected);
        for (const key of ['line', 'column', 'position'])
          assert.equal(error.cause[key], location[key]);
        assert.ok(error.cause instanceof InputError);
        assert.equal(error.cause.cause, undefined);
        assert.ok(!inspect(error, { depth: 10 }).includes('BADSECRET'));
        return true;
      }
    );
  }
});

test('large numeric source IDs and counters never hang allocation or reuse old IDs', t => {
  const moduleUrl = new URL('../lib/config.mjs', import.meta.url).href;
  for (const suffix of ['9007199254740992', '9'.repeat(70), null]) {
    const directory = temporary(t),
      config = new ConfigStore(directory),
      existing = suffix ? 'json-' + suffix : null;
    config.value.services = existing ? [{ ...newService('json'), id: existing }] : [];
    config.value.sourceCounters = suffix ? {} : { json: Number.MAX_SAFE_INTEGER };
    config.save();
    // An allocator regression must fail this test, not freeze the entire test process.
    const child = spawnSync(
      process.execPath,
      [
        '--input-type=module',
        '-e',
        `import { ConfigStore } from ${JSON.stringify(moduleUrl)};
         const first = new ConfigStore(process.argv[1]);
         const a = first.add({ type: 'json' }).id;
         first.remove(a);
         const second = new ConfigStore(process.argv[1]);
         const b = second.add({ type: 'json' }).id;
         console.log(JSON.stringify({ a, b, counter: second.value.sourceCounters.json }));`,
        directory,
      ],
      { encoding: 'utf8', timeout: 5000 }
    );
    assert.equal(child.error, undefined, 'source allocation must finish promptly');
    assert.equal(child.status, 0, child.stderr);
    const { a, b, counter } = JSON.parse(child.stdout);
    for (const id of [a, b]) {
      assert.match(id, /^json-[0-9a-f-]{36}$/);
      assert.notEqual(id, existing);
    }
    assert.notEqual(a, b);
    assert.equal(counter, Number.MAX_SAFE_INTEGER);
  }
});

// The audit's start rows say a change of the configuration may be a repair made at load (audit
// spec §5.6 step 3): ConfigStore#repaired.
test('ConfigStore#repaired: true when values were repaired at load, false otherwise', t => {
  const directory = temporary(t);
  const fresh = new ConfigStore(directory);
  assert.equal(fresh.repaired, false, 'a new file');
  assert.equal(new ConfigStore(directory).repaired, false, 'a valid file');
  const saved = JSON.parse(fs.readFileSync(fresh.file, 'utf8'));
  saved.appearance.timezone = 'UTC+00:00';
  fs.writeFileSync(fresh.file, JSON.stringify(saved));
  const warned = [];
  t.mock.method(console, 'warn', (...args) => warned.push(args.join(' ')));
  const repaired = new ConfigStore(directory);
  assert.equal(repaired.repaired, true);
  assert.equal(repaired.value.appearance.timezone, 'UTC');
  assert.equal(warned.length, 1);
  assert.equal(new ConfigStore(directory).repaired, false, 'saved once, so not repaired again');
});

// A repair warning reaches Uptime Goblin's log (and the audit canary's stderr): an apiUrl is never named
// in it, as a destination with credentials already is not ("(hidden)"). Codex review A4: naming
// it without its query, fragment and user info still logged a secret in its path.
test('apiUrl warning: an apiUrl with ?token=… is repaired with a warning that names neither address', t => {
  const directory = temporary(t);
  const config = new ConfigStore(directory);
  const saved = JSON.parse(fs.readFileSync(config.file, 'utf8'));
  const source = saved.services[0];
  source.apiUrl =
    'https://user:SECRET-PASS@nas.example.com:5001/webapi?token=SECRET-TOKEN#frag=SECRET-FRAG';
  saved.services[1].apiUrl = 'not a url?token=SECRET-TOKEN2';
  fs.writeFileSync(config.file, JSON.stringify(saved));
  const warned = [];
  t.mock.method(console, 'warn', (...args) => warned.push(args.join(' ')));
  const repaired = new ConfigStore(directory);
  assert.equal(repaired.repaired, true);
  assert.equal(repaired.value.services[0].apiUrl, '');
  assert.equal(repaired.value.services[1].apiUrl, '');
  const text = warned.join('\n');
  for (const { id } of saved.services.slice(0, 2))
    assert.match(text, new RegExp(`collection address of ${id} "\\(hidden\\)" was replaced by ""`));
  assert.doesNotMatch(text, /SECRET|token|frag|nas\.example|webapi|not a url/);
});

// A bare '?' is repaired to the same address without it; neither side is named, so neither a
// password before the host nor a secret in the path that the repair keeps reaches the log.
test('apiUrl warning: an apiUrl with user info, a secret path and a bare ? names neither side', t => {
  const directory = temporary(t);
  const config = new ConfigStore(directory);
  const saved = JSON.parse(fs.readFileSync(config.file, 'utf8'));
  const source = saved.services[0];
  source.apiUrl = 'https://user:SECRET-PASS@nas.example.com:5001/SECRET-PATH/webapi?';
  fs.writeFileSync(config.file, JSON.stringify(saved));
  const warned = [];
  t.mock.method(console, 'warn', (...args) => warned.push(args.join(' ')));
  // The address keeps its user info, so validation then refuses the file; the warning came first.
  assert.throws(() => new ConfigStore(directory), /without credentials/);
  const text = warned.join('\n');
  assert.match(
    text,
    new RegExp(
      `collection address of ${source.id} "\\(hidden\\)" was replaced by "the same address without its empty query or fragment markers"`
    )
  );
  assert.doesNotMatch(text, /SECRET|user:|nas\.example|webapi/);
});

test('config.json whose bytes are not UTF-8 refuses the start (78) instead of saving U+FFFD into its values', t => {
  const directory = temporary(t),
    file = path.join(directory, 'config.json');
  // A password typed in another encoding by a hand edit: it was loaded as two U+FFFD.
  const prefix = '{"services":[],"email":{"password":"',
    suffix = '"}}';
  fs.writeFileSync(
    file,
    Buffer.concat([Buffer.from(prefix), Buffer.from([0xff, 0xfe]), Buffer.from(suffix)])
  );
  for (const read of [() => checkConfigFile(directory), () => new ConfigStore(directory)])
    assert.throws(
      read,
      error =>
        error.refusal === true &&
        error.message ===
          `Invalid configuration file ${file}: it is not valid UTF-8 text; save it as UTF-8. Correct it or restore a backup, then start Uptime Goblin again.`
    );
  // The same text in UTF-8 loads, other scripts included; a byte order mark is still refused.
  fs.writeFileSync(file, `{"services":[],"title":"Büro – 東京"}`);
  assert.equal(new ConfigStore(directory).value.title, 'Büro – 東京');
  fs.writeFileSync(file, '﻿{"services":[]}');
  assert.throws(() => checkConfigFile(directory), /Expected valid JSON/);
});

test('a member name given twice, or __proto__, in config.json is reported by its place once and saved away; the last value is kept', t => {
  const directory = temporary(t),
    file = path.join(directory, 'config.json');
  fs.writeFileSync(
    file,
    '{"services":[{"id":"linux-1","type":"linux","name":"first","name":"second","__proto__":{"apiKey":"SYNTH-PROTO-CANARY"}}],' +
      '"title":"one","title":"two","sp\\u001bam":1,"sp\\u001bam":2}'
  );
  const warnings = [];
  t.mock.method(console, 'warn', (...args) => warnings.push(args.join(' ')));
  const config = new ConfigStore(directory);
  assert.equal(config.value.title, 'two', 'last wins, as in 1.4.x');
  assert.equal(config.value.services[0].name, 'second');
  assert.deepEqual(warnings, [
    'Configuration: services[0].name is given more than once in config.json; the last one is used.',
    'Configuration: services[0].__proto__ in config.json is not a setting and is ignored.',
    'Configuration: title is given more than once in config.json; the last one is used.',
    'Configuration: spam is given more than once in config.json; the last one is used.',
  ]);
  assert.ok(!warnings.join('\n').includes('SYNTH-PROTO-CANARY'));
  assert.equal(config.repaired, true);
  const saved = fs.readFileSync(file, 'utf8');
  assert.ok(!saved.includes('__proto__') && !saved.includes('"one"'), 'saved without them');
  // The saved file loads quietly.
  warnings.length = 0;
  new ConfigStore(directory);
  assert.deepEqual(warnings, []);
  assert.equal(Object.prototype.apiKey, undefined);
});

test('metric label keys longer than 100 characters are refused, from the API and from config.json', t => {
  const mapping = labels => ({
    services: [
      {
        id: 'json-1',
        type: 'json',
        metrics: [{ key: 'a', path: 'a', labels }],
      },
    ],
  });
  const directory = temporary(t),
    file = path.join(directory, 'config.json');
  fs.writeFileSync(file, JSON.stringify(mapping({ ['k'.repeat(100)]: 'v' })));
  const config = new ConfigStore(directory);
  assert.deepEqual(config.value.services[0].metrics[0].labels, { ['k'.repeat(100)]: 'v' });
  assert.throws(
    () =>
      config.update('json-1', {
        metrics: [{ key: 'a', path: 'a', labels: { ['k'.repeat(101)]: 'v' } }],
      }),
    /Invalid label key/
  );
  fs.writeFileSync(file, JSON.stringify(mapping({ ['k'.repeat(100000)]: 'v' })));
  assert.throws(() => checkConfigFile(directory), /Invalid label key/);
});

test('repair warnings name a source by a valid ID or by its place, never by saved text', t => {
  const warnings = [];
  const directory = temporary(t);
  fs.writeFileSync(
    path.join(directory, 'config.json'),
    JSON.stringify({
      services: [
        {
          id: 'x\u001b[2J\n[orbit] SYNTH-ID-CANARY',
          type: 'proxmox',
          apiUrl: 'http://h.example.test/?',
        },
      ],
    })
  );
  t.mock.method(console, 'warn', (...args) => warnings.push(args.join(' ')));
  // The ID is refused after the repairs ran: the warning before it must not carry the ID.
  assert.throws(() => new ConfigStore(directory), /source 1 has a duplicate or invalid ID/);
  assert.deepEqual(warnings, [
    'Configuration: collection address of source 1 "(hidden)" was replaced by "the same address without its empty query or fragment markers".',
  ]);
});
