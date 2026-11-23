// The small Markdown renderer for the Help page (escapes everything it does not render).
import { esc } from '../core/dom.js';

function markdownInline(text) {
  const tokens = [];
  const token = html => {
    tokens.push(html);
    return `\u0000${tokens.length - 1}\u0000`;
  };
  text = String(text)
    .replace(/\u0000/g, '')
    .replace(/`([^`]+)`/g, (_, code) => token(`<code>${esc(code)}</code>`));
  text = text.replace(/\[([^\]\n]+)\]\(([^\s)]+)\)/g, (_, label, url) => {
    const local = url.match(
      /^(?:\.\/)?(?:docs\/)?(installation|configuration|notifications|integrations|architecture|security|authentication|troubleshooting)\.md(?:#[\w-]+)?$/i
    );
    if (local)
      return token(
        `<button class="doc-inline-link" type="button" data-doc="${local[1].toLowerCase()}">${esc(label)}</button>`
      );
    try {
      const target = new URL(url);
      if (['https:', 'http:'].includes(target.protocol) && !target.username && !target.password)
        return token(
          `<a href="${esc(target.href)}" target="_blank" rel="noopener noreferrer">${esc(label)}</a>`
        );
    } catch {}
    return token(esc(label));
  });
  return esc(text)
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/\u0000(\d+)\u0000/g, (_, index) => tokens[Number(index)]);
}
export function renderMarkdown(markdown) {
  const lines = String(markdown).replace(/\r\n/g, '\n').split('\n'),
    output = [];
  let index = 0;
  const comment = /^\s*<!--.*-->\s*$/;
  const tableCells = line =>
    line
      .trim()
      .replace(/^\||\|$/g, '')
      .split('|')
      .map(cell => cell.trim());
  while (index < lines.length) {
    const line = lines[index];
    // A line that is one HTML comment (the dev-only and public-note markers of the source
    // guides, which the public export removes) is not shown.
    if (!line.trim() || comment.test(line)) {
      index++;
      continue;
    }
    if (/^\s*```/.test(line)) {
      const code = [];
      index++;
      while (index < lines.length && !/^\s*```/.test(lines[index])) code.push(lines[index++]);
      if (index < lines.length) index++;
      output.push(`<pre><code>${esc(code.join('\n'))}</code></pre>`);
      continue;
    }
    const heading = line.match(/^(#{1,6})\s+(.+)$/);
    if (heading) {
      if (heading[1].length === 1 && !output.length) {
        index++;
        continue;
      }
      const level = Math.min(4, heading[1].length + 1);
      output.push(`<h${level}>${markdownInline(heading[2])}</h${level}>`);
      index++;
      continue;
    }
    if (
      index + 1 < lines.length &&
      line.includes('|') &&
      /^\s*\|?\s*:?-{3,}:?\s*(?:\|\s*:?-{3,}:?\s*)+\|?\s*$/.test(lines[index + 1])
    ) {
      const headers = tableCells(line);
      index += 2;
      const rows = [];
      while (index < lines.length && lines[index].includes('|') && lines[index].trim())
        rows.push(tableCells(lines[index++]));
      output.push(
        `<div class="table-scroll"><table><thead><tr>${headers.map(cell => `<th scope="col">${markdownInline(cell)}</th>`).join('')}</tr></thead><tbody>${rows.map(row => `<tr>${headers.map((_, i) => `<td>${markdownInline(row[i] || '')}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`
      );
      continue;
    }
    const list = line.match(/^\s*(?:([-*+])|(\d+)[.)])\s+(.+)$/);
    if (list) {
      const ordered = !!list[2],
        items = [];
      while (index < lines.length) {
        const item = lines[index].match(/^\s*(?:([-*+])|(\d+)[.)])\s+(.+)$/);
        if (!item || !!item[2] !== ordered) break;
        items.push(markdownInline(item[3]));
        index++;
      }
      output.push(
        `<${ordered ? 'ol' : 'ul'}>${items.map(item => `<li>${item}</li>`).join('')}</${ordered ? 'ol' : 'ul'}>`
      );
      continue;
    }
    if (/^\s*(?:---+|\*\*\*+)\s*$/.test(line)) {
      output.push('<hr>');
      index++;
      continue;
    }
    const paragraph = [line];
    index++;
    while (
      index < lines.length &&
      lines[index].trim() &&
      !comment.test(lines[index]) &&
      !/^(?:#{1,6}\s|\s*```|\s*[-*+]\s|\s*\d+[.)]\s)/.test(lines[index]) &&
      !(lines[index].includes('|') && /^\s*\|?\s*:?-{3,}/.test(lines[index + 1] || ''))
    )
      paragraph.push(lines[index++]);
    output.push(`<p>${markdownInline(paragraph.join(' '))}</p>`);
  }
  return output.join('');
}
