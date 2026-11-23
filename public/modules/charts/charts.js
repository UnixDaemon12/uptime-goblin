// An expanded card's history chart: fetching, drawing and the pointer tooltip.
import { api } from '../core/api.js';
import { $, esc, icon } from '../core/dom.js';
import { dateTime, format } from '../core/format.js';
import { page, stateFor } from '../core/page.js';
import { patchHtml } from '../core/patch.js';
import { restoreScroll } from '../update/update.js';

let historyRequest = null,
  chartPointer = null;
// Only the expanded card's history is kept: a large source's history can be many MB.
const historyCache = new Map();
const charts = new Map();
/** Drops history kept for cards other than the expanded one. */
export function forgetHistory() {
  for (const map of [historyCache, charts])
    for (const id of map.keys()) if (id !== page.expanded) map.delete(id);
}
/**
 * Whether the expanded card's history should be fetched again. A chart only gains a new
 * bucket every range/300, so it is refreshed once its window has moved on by a bucket (at
 * most once per 15 s poll), also while no readings arrive, e.g. when paused. A change of
 * status (paused, resumed, failing, recovered) shows at once, and so does the next reading
 * after this tab's own Refresh or change to the source (refreshHistory).
 */
export function historyDue(id) {
  const cached = historyCache.get(id);
  if (!cached || cached.range !== page.range || cached.error || cached.metric !== metricFor(id))
    return true;
  const state = stateFor(id);
  return (
    state.status !== cached.status ||
    (cached.followReading && (state.lastAttempt ?? state.lastSuccess) !== cached.lastAttempt) ||
    Date.now() - cached.fetchedAt >= Math.max(15000, (cached.to - cached.from) / 300)
  );
}
/**
 * After this tab's own Refresh or change to a source, its open chart is fetched again at the
 * next load, and once more when the next reading or failure arrives.
 */
export function refreshHistory(id) {
  const cached = historyCache.get(id);
  if (cached) Object.assign(cached, { fetchedAt: -Infinity, followReading: true });
}
/** The measurement the card's chart shows: the one selected, or else the first. */
function metricFor(id) {
  const metrics = stateFor(id).metrics || [];
  return metrics.some(m => m.key === page.selectedMetric)
    ? page.selectedMetric
    : metrics[0]?.key || '';
}
/**
 * Fetches the history the card `id` charts. `background`: the fetch a poll started (the chart's
 * window moved on), which says so like the poll itself, so an open chart does not keep an idle
 * session signed in; a person's action (expanding a card, choosing a range or a measurement,
 * saving) is never background.
 */
export function loadHistory(id, { background = false } = {}) {
  if (!id || !stateFor(id).metrics?.length) return;
  const requestedRange = page.range,
    metric = metricFor(id),
    { status } = stateFor(id),
    lastAttempt = stateFor(id).lastAttempt ?? stateFor(id).lastSuccess;
  if (
    historyRequest?.id === id &&
    historyRequest.range === requestedRange &&
    historyRequest.metric === metric
  )
    return historyRequest.promise;
  const request = { id, range: requestedRange, metric };
  historyRequest = request;
  request.promise = (async () => {
    try {
      // Only the charted measurement: a large source reports hundreds of readings.
      const history = await api(
        `/api/history/${encodeURIComponent(id)}?range=${requestedRange}&metric=${encodeURIComponent(metric)}`,
        { background }
      );
      // A response for a period, card or measurement the user has left is never drawn.
      if (page.expanded !== id || page.range !== requestedRange || metricFor(id) !== metric) return;
      const previous = historyCache.get(id);
      historyCache.set(id, {
        ...history,
        range: requestedRange,
        metric,
        fetchedAt: Date.now(),
        lastAttempt,
        status,
        // Keep watching after the fetch refreshHistory() forced, and until one brings a
        // newer reading: that fetch may have run before the reading arrived.
        followReading:
          !!previous?.followReading &&
          (previous.fetchedAt === -Infinity || previous.lastAttempt === lastAttempt),
      });
    } catch (e) {
      if (page.expanded !== id || page.range !== requestedRange || metricFor(id) !== metric) return;
      // Readings already drawn for this period stay; the next poll tries again.
      const cached = historyCache.get(id);
      if (cached?.range !== requestedRange || cached.metric !== metric || cached.error)
        historyCache.set(id, {
          range: requestedRange,
          metric,
          error: e.message,
          fetchedAt: Date.now(),
        });
    } finally {
      if (historyRequest === request) historyRequest = null;
    }
    renderGraph(id);
  })();
  return request.promise;
}
export function renderGraph(id) {
  const history = historyCache.get(id),
    state = stateFor(id),
    element = $(`#graph-${CSS.escape(id)}`);
  // Skip while the dashboard is hidden: the layout has no width to draw to.
  if (!element || !element.getClientRects().length) return;
  if (!history || history.range !== page.range || history.error) {
    charts.delete(id);
    patchHtml(
      element,
      history?.range === page.range
        ? `<div class="detail-error">History is unavailable. ${esc(history.error)}</div>`
        : '<div class="loading">Loading history…</div>'
    );
    // An error is this card's final height too.
    if (history?.range === page.range) restoreScroll(true);
    return;
  }
  const metrics = state.metrics;
  if (!metrics.some(m => m.key === page.selectedMetric)) page.selectedMetric = metrics[0]?.key;
  const current = metrics.find(m => m.key === page.selectedMetric);
  if (!current) {
    restoreScroll(true);
    return;
  }
  const points = history.points.map(p => ({
    time: p.time,
    gapBefore: p.gapBefore,
    value: p.ok ? p.metrics.find(m => m.key === page.selectedMetric)?.value : null,
  }));
  const valid = points.filter(p => Number.isFinite(p.value));
  let chart;
  if (history.metric !== page.selectedMetric) {
    // Another measurement was chosen: keep the controls, and fetch its history.
    charts.delete(id);
    chart = '<div class="loading chart-loading">Loading history…</div>';
    void loadHistory(id);
  } else if (!valid.length) {
    charts.delete(id);
    chart = `<div class="empty-history compact"><div class="empty-symbol">${icon('chart', 23)}</div><h4>No readings in this period</h4><p>Try a longer time range or allow this source to collect new readings.</p></div>`;
  } else {
    // Match the drawing to the chart's CSS box so it is not scaled or letterboxed.
    const style = getComputedStyle(element),
      w = Math.max(250, parseFloat(style.gridTemplateColumns) || 700),
      h = parseFloat(style.getPropertyValue('--chart-height')) || 205,
      left = 67,
      right = 12,
      top = 18,
      bottom = 34;
    let min = Math.min(...valid.map(p => p.value)),
      max = Math.max(...valid.map(p => p.value));
    if (min === max) {
      const pad = Math.max(Math.abs(max) * 0.05, 1);
      min = min >= 0 ? Math.max(0, min - pad) : min - pad;
      max += pad;
    } else {
      const pad = (max - min) * 0.12;
      min = min >= 0 ? Math.max(0, min - pad) : min - pad;
      max += pad;
    }
    const x = t => left + ((t - history.from) / (history.to - history.from)) * (w - left - right),
      y = v => top + ((max - v) / (max - min)) * (h - top - bottom);
    // The server's maxGapMs allows for collection time on top of the interval; older
    // servers only report the interval. Downsampled points also sit a bucket or two apart.
    const maxGap = Math.max(
      Number.isFinite(history.maxGapMs) ? history.maxGapMs : history.pollSeconds * 3000,
      ((history.to - history.from) / 300) * 2.5
    );
    const segments = [];
    let previous = null;
    for (const p of points) {
      if (!Number.isFinite(p.value)) {
        previous = null;
        continue;
      }
      if (!previous || p.gapBefore || p.time - previous.time > maxGap) segments.push([]);
      segments.at(-1).push(`${x(p.time).toFixed(2)} ${y(p.value).toFixed(2)}`);
      previous = p;
    }
    // A reading between two failures or gaps is a zero-length segment, which the round
    // line cap draws as a dot; a bare moveto would draw nothing.
    const line = segments
      .map(
        ([first, ...rest]) => ` M${first}${rest.length ? rest.map(p => ' L' + p).join('') : ' h0'}`
      )
      .join('');
    const ticks = Array.from({ length: 4 }, (_, i) => {
      const value = min + ((max - min) * i) / 3;
      return `<line class="chart-grid" x1="${left}" x2="${w - right}" y1="${y(value)}" y2="${y(value)}"/><text class="chart-axis" x="${left - 9}" y="${y(value) + 4}" text-anchor="end">${esc(format(value, current.unit))}</text>`;
    }).join('');
    const timeLabels = [0, 0.5, 1]
      .map(f => {
        const t = history.from + (history.to - history.from) * f;
        const label = dateTime(
          t,
          history.to - history.from > 86400000
            ? { month: 'short', day: 'numeric' }
            : { hour: '2-digit', minute: '2-digit' }
        );
        return `<text class="chart-axis" x="${x(t)}" y="${h - 5}" text-anchor="${f === 0 ? 'start' : f === 1 ? 'end' : 'middle'}">${esc(label)}</text>`;
      })
      .join('');
    chart = `<svg class="chart" data-chart="${esc(id)}" viewBox="0 0 ${w} ${h}" role="img" tabindex="0" aria-label="${esc(current.label)} history. ${valid.length} sampled reading${valid.length === 1 ? '' : 's'}. Lowest ${esc(format(Math.min(...valid.map(p => p.value)), current.unit))}, highest ${esc(format(Math.max(...valid.map(p => p.value)), current.unit))}. Collection gaps are left blank.">${ticks}${timeLabels}<path class="chart-line" d="${line}"/>${valid
      .filter((p, i) => i === valid.length - 1)
      .map(p => `<circle cx="${x(p.time)}" cy="${y(p.value)}" r="3.5" fill="var(--accent)"/>`)
      .join(
        ''
      )}</svg><p class="graph-tooltip" id="graph-tooltip">${esc(valid.length === 1 ? (history.totalSamples > 1 ? '1 sampled reading · choose a shorter range for more detail' : 'First reading saved · history builds over time') : valid.length + ' sampled readings · hover for details')}</p>`;
    const failures = history.points.filter(p => !p.ok);
    charts.set(id, { valid, failures, history, current, w, left, right });
  }
  patchHtml(
    element,
    `<div class="graph-wrap"><div class="chart-label"><label for="metric-select">Measurement</label><span>${esc(format(current.value, current.unit))}</span></div><select id="metric-select" class="metric-select">${metrics.map(m => `<option value="${esc(m.key)}" ${m.key === page.selectedMetric ? 'selected' : ''}>${esc(m.label)}</option>`).join('')}</select>${chart}</div><div class="detail-stats">${metrics.map(m => `<div class="stat-row"><span>${esc(m.label)}</span><strong>${esc(format(m.value, m.unit))}</strong></div>`).join('')}</div>`
  );
  $('#metric-select').value = page.selectedMetric;
  // Keep the tooltip on the point under a pointer that is still over the redrawn chart.
  const svg = element.querySelector('svg.chart');
  if (svg && chartPointer && svg.matches(':hover')) showChartTooltip(svg, chartPointer);
  // The chart (or its "no readings" note) has its height now, so an update reload can return
  // to the same place.
  if (history.metric === page.selectedMetric) restoreScroll(true);
}
function showChartTooltip(svg, { clientX, clientY }) {
  const chart = charts.get(svg.dataset.chart),
    matrix = svg.getScreenCTM();
  if (!chart || !matrix) return;
  // Map through the SVG's own transform, which includes any scaling or letterboxing.
  const vx = new DOMPoint(clientX, clientY).matrixTransform(matrix.inverse()).x;
  const t =
    chart.history.from +
    ((vx - chart.left) / (chart.w - chart.left - chart.right)) *
      (chart.history.to - chart.history.from);
  const closest = list =>
    list.reduce((a, b) => (Math.abs(b.time - t) < Math.abs(a.time - t) ? b : a));
  const nearest = closest(chart.valid),
    failure = chart.failures?.length ? closest(chart.failures) : null;
  const tip = $('#graph-tooltip');
  if (!tip) return;
  // A failed collection closer to the pointer than any reading shows why it failed.
  tip.textContent =
    failure && Math.abs(failure.time - t) < Math.abs(nearest.time - t)
      ? failure.gap
        ? `${dateTime(failure.time)} · No collection (paused or reconfigured)`
        : `${dateTime(failure.time)} · Collection failed${failure.error ? ': ' + failure.error : ''}`
      : `${dateTime(nearest.time)} · ${format(nearest.value, chart.current.unit)}`;
}
let resizeFrame;

/**
 * Registers this module’s event handlers (and, where noted, reads what the page needs at
 * start). main.js calls it once, keeping the order in which public/app.js registered them.
 */
export function install() {
  document.addEventListener('pointermove', e => {
    const svg = e.target.closest('[data-chart]');
    chartPointer = svg ? { clientX: e.clientX, clientY: e.clientY } : null;
    if (svg) showChartTooltip(svg, e);
  });
  window.addEventListener('resize', () => {
    cancelAnimationFrame(resizeFrame);
    resizeFrame = requestAnimationFrame(() => {
      if (page.expanded) renderGraph(page.expanded);
    });
  });
}
