// Parsers for the pinned gate reports. Unsupported or incomplete reports fail closed.
// Finding IDs bind the whole raw record and report, not a broad rule/path exemption.
import { sha256 } from './security-evidence.mjs';

export const findingReports = {
  'secrets-source': 'secrets-source.json',
  'secrets-history': 'secrets-history.json',
  'secrets-metadata': 'secrets-metadata.json',
  'source-analysis': 'source-analysis.json',
  'container-configuration': 'container-configuration.json',
  'container-vulnerabilities': 'container-security.json',
};

function requireValue(condition) {
  if (!condition) throw new Error('Incomplete or unsupported scanner report');
}
const text = value => typeof value === 'string' && value.length > 0;
const list = value => Array.isArray(value);
const positive = value => Number.isSafeInteger(value) && value > 0;

export function reportFindings(stage, bytes, { tools, files }) {
  let report;
  try {
    report = JSON.parse(bytes.toString('utf8'));
  } catch {
    throw new Error('Cannot parse scanner report');
  }
  const findings = [];
  const reportSha256 = sha256(bytes);
  const add = (raw, rule, target) => {
    requireValue(text(rule) && text(target));
    const occurrence = findings.length;
    findings.push({
      id: sha256(JSON.stringify([stage, reportSha256, occurrence, raw])),
      stage,
      reportSha256,
      occurrence,
      rule,
      target,
    });
  };
  if (stage.startsWith('secrets-') && findingReports[stage]) {
    requireValue(tools.gitleaks === '8.30.1' && list(report));
    for (const item of report) {
      requireValue(
        item &&
          positive(item.StartLine) &&
          positive(item.EndLine) &&
          item.EndLine >= item.StartLine &&
          text(item.Fingerprint) &&
          (stage !== 'secrets-history' || /^[a-f0-9]{40,64}$/.test(item.Commit))
      );
      add(item, item.RuleID, item.File);
    }
  } else if (stage === 'source-analysis') {
    requireValue(
      report?.version === '1.176.0' &&
        tools.semgrepImage ===
          'semgrep/semgrep:1.176.0@sha256:12672acdb0949e19f9f6a4c2b288edd0b404f268f0ca7738a2c06f372f50362e' &&
        tools.semgrepRulesCommit === 'a84ff9cc2453ca91d581380de4b8b3f272f6f4be' &&
        tools.semgrepRulesSha256 ===
          'b227c2d234ffd9c84c4dbd6619a5897a7192637c141baeace3bfc37b0715a887' &&
        list(report.results) &&
        list(report.errors) &&
        report.errors.length === 0 &&
        list(report.skipped_rules) &&
        report.skipped_rules.length === 0 &&
        list(report.paths?.scanned) &&
        report.paths.scanned.length > 0 &&
        (!report.paths.skipped || (list(report.paths.skipped) && report.paths.skipped.length === 0))
    );
    const scanned = new Set(report.paths.scanned.map(file => file.replace(/^\.\//, '')));
    requireValue(
      files
        .filter(({ file }) => /\.(?:mjs|cjs|js)$/.test(file))
        .every(({ file }) => scanned.has(file))
    );
    for (const item of report.results) {
      requireValue(
        positive(item?.start?.line) &&
          positive(item?.end?.line) &&
          item.extra &&
          item.extra.is_ignored !== true &&
          scanned.has(item.path.replace(/^\.\//, ''))
      );
      add(item, item.check_id, item.path);
    }
  } else if (stage.startsWith('container-') && findingReports[stage]) {
    requireValue(
      tools.trivy === '0.74.0' &&
        report?.SchemaVersion === 2 &&
        report.Trivy?.Version === tools.trivy &&
        list(report.Results) &&
        report.Results.length > 0 &&
        text(report.ArtifactID) &&
        text(report.ArtifactName)
    );
    if (stage === 'container-vulnerabilities') {
      requireValue(
        /^sha256:[a-f0-9]{64}$/.test(report.Metadata?.ImageID) &&
          report.Results.some(item => item.Class === 'os-pkgs') &&
          report.Results.some(item => item.Class === 'lang-pkgs') &&
          report.Results.some(item => item.Class === 'config')
      );
    } else {
      const targets = new Set(report.Results.map(item => item.Target));
      requireValue(
        files
          .filter(({ file }) => /(?:^|\/)[^/]*dockerfile[^/]*$/i.test(file))
          .every(({ file }) => targets.has(file))
      );
    }
    for (const item of report.Results) {
      requireValue(text(item.Target) && !item.Error);
      for (const key of ['Vulnerabilities', 'Misconfigurations', 'Secrets'])
        requireValue(item[key] === undefined || list(item[key]));
      const misconfigurations = item.Misconfigurations || [];
      if (item.Class === 'config') {
        requireValue(
          Number.isSafeInteger(item.MisconfSummary?.Successes) &&
            item.MisconfSummary.Successes >= 0 &&
            item.MisconfSummary.Failures === misconfigurations.length &&
            !item.MisconfSummary.Exceptions
        );
      }
      for (const finding of item.Vulnerabilities || []) {
        requireValue(
          text(finding.PkgName) && text(finding.InstalledVersion) && text(finding.Severity)
        );
        add(
          { target: item.Target, image: report.Metadata?.ImageID, ...finding },
          finding.VulnerabilityID,
          item.Target
        );
      }
      for (const finding of misconfigurations) {
        requireValue(finding.Status === 'FAIL' && text(finding.Severity));
        add({ target: item.Target, ...finding }, finding.ID, item.Target);
      }
      for (const finding of item.Secrets || []) {
        requireValue(positive(finding.StartLine) && text(finding.Severity));
        add({ target: item.Target, ...finding }, finding.RuleID, item.Target);
      }
    }
  } else throw new Error('Unsupported scanner stage');
  return findings;
}
