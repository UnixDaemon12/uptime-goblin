// Configuration and history exports.
import { api } from '../core/api.js';
import { toast } from '../core/dom.js';
import { holdFocus } from '../core/forms.js';
import { page } from '../core/page.js';
import { csvCell } from '../../shared/csv.js';

/** Saves `content` (text, or the bytes of a download) as the file `name`. */
export function downloadFile(name, content, type) {
  const url = URL.createObjectURL(new Blob([content], { type })),
    a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
export async function exportConfiguration(button) {
  // The button is disabled until the download starts: holdFocus() keeps its focus, through a
  // sign-in dialog the request may open too.
  const release = holdFocus(button);
  button.disabled = true;
  try {
    const result = await api('/api/config/export');
    downloadFile(
      'uptime-goblin-config-redacted.json',
      JSON.stringify(result, null, 2) + '\n',
      'application/json'
    );
    toast('Configuration exported. Private hostnames are included.');
  } catch (e) {
    toast(e.message);
  } finally {
    button.disabled = false;
    release();
  }
}
export async function exportHistory(id, selectedRange, button) {
  if (!id) {
    toast('Add a source before exporting readings.');
    return;
  }
  const release = holdFocus(button);
  button.disabled = true;
  try {
    const history = await api(
        `/api/history/${encodeURIComponent(id)}?range=${encodeURIComponent(selectedRange)}`
      ),
      source = page.data.config.services.find(s => s.id === id);
    if (!history.points.length) {
      toast('There are no saved readings in this period.');
      return;
    }
    // Keys, labels and units come from the source's API, and errors describe what it sent, so
    // every cell but a numeric value goes through the formula guard (csvCell).
    const rows = [
      ['timestamp_utc', 'status', 'gap_before', 'metric', 'label', 'value', 'unit', 'error'],
    ];
    for (const p of history.points) {
      if (!p.ok)
        rows.push([
          new Date(p.time).toISOString(),
          p.gap ? 'gap' : 'failed',
          !!p.gapBefore,
          '',
          '',
          '',
          '',
          p.error ?? '',
        ]);
      else
        for (const metric of p.metrics)
          rows.push([
            new Date(p.time).toISOString(),
            'ok',
            !!p.gapBefore,
            metric.key,
            metric.label,
            metric.value,
            metric.unit,
            '',
          ]);
    }
    // The byte order mark makes Excel read the file as UTF-8 rather than a legacy code
    // page, which would garble the '·', '’' and '…' in labels and error text.
    downloadFile(
      `uptime-goblin-${source?.id || id}-${selectedRange}.csv`,
      '\ufeff' +
        rows
          .map(row =>
            row
              .map((value, i) =>
                i === 5 && typeof value === 'number' ? String(value) : csvCell(value)
              )
              .join(',')
          )
          .join('\r\n') +
        '\r\n',
      'text/csv;charset=utf-8'
    );
    toast('Sampled history exported.');
  } catch (e) {
    toast(e.message);
  } finally {
    button.disabled = false;
    release();
  }
}
