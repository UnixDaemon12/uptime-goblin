// The Help page: loads a guide.
import { api } from '../core/api.js';
import { $, esc } from '../core/dom.js';
import { renderMarkdown } from './markdown.js';

let documentationRequest = 0;
export async function loadDocumentation(doc) {
  const request = ++documentationRequest,
    target = $('#documentation');
  if (!target) return;
  document
    .querySelectorAll('[data-doc]')
    .forEach(b => b.setAttribute('aria-pressed', String(b.dataset.doc === doc)));
  target.innerHTML = '<p class="loading">Opening guide…</p>';
  try {
    const result = await api('/api/docs?doc=' + encodeURIComponent(doc));
    if (request !== documentationRequest || target !== $('#documentation')) return;
    target.innerHTML = `<h3>${esc(result.title)}</h3><div class="documentation-body">${renderMarkdown(result.markdown)}</div>`;
  } catch (e) {
    if (request === documentationRequest && target === $('#documentation'))
      target.innerHTML = `<p class="field-error" role="alert">${esc(e.message)}</p><button class="button" type="button" data-doc="${esc(doc)}">Try again</button>`;
  }
}
