// Patches rendered HTML into the page, keeping nodes that did not change (focus, open selects).

// Brings `target`'s children in line with `html` but keeps nodes that did not change, so
// a refresh does not drop focus, close an open <select> or reset hover state.
export function patchHtml(target, html) {
  const template = document.createElement('template');
  template.innerHTML = html;
  patchChildren(target, template.content);
}
const nodeKey = node =>
  node.nodeType === 1 ? node.id || node.dataset?.id || node.dataset?.group || '' : '';
const sameNode = (a, b) => a.nodeName === b.nodeName && nodeKey(a) === nodeKey(b);
function patchChildren(target, source) {
  const nodes = [...source.childNodes],
    // Keys still to be placed: a keyed node whose key is not among them was removed.
    pending = new Set(nodes.map(nodeKey).filter(Boolean));
  let current = target.firstChild;
  for (const node of nodes) {
    const key = nodeKey(node);
    // A keyed node further on is moved into place (a reorder, e.g. 'Needs attention first'),
    // so nothing is rebuilt. Removed nodes before it go. Nodes still to come are moved out
    // of its way when it holds the focus, since moving the focused node would blur it and
    // close an open dropdown; otherwise it is moved up to them.
    if (current && key && !sameNode(current, node)) {
      let later = current.nextSibling;
      while (later && !sameNode(later, node)) later = later.nextSibling;
      while (later && current !== later) {
        if (pending.has(nodeKey(current)) && !later.contains(document.activeElement)) {
          target.insertBefore(later, current);
          current = later;
        } else {
          const next = current.nextSibling;
          if (pending.has(nodeKey(current))) target.append(current);
          else current.remove();
          current = next;
        }
      }
    }
    pending.delete(key);
    if (current && sameNode(current, node)) {
      if (!current.isEqualNode(node)) patchNode(current, node);
      current = current.nextSibling;
    } else target.insertBefore(node, current);
  }
  while (current) {
    const removed = current;
    current = current.nextSibling;
    removed.remove();
  }
}
function patchNode(current, node) {
  if (current.nodeType !== 1) {
    current.nodeValue = node.nodeValue;
    return;
  }
  for (const { name } of [...current.attributes])
    if (!node.hasAttribute(name)) current.removeAttribute(name);
  for (const { name, value } of node.attributes)
    if (current.getAttribute(name) !== value) current.setAttribute(name, value);
  // renderGraph() owns the chart area and redraws it itself.
  if (!current.hasAttribute('data-graph')) patchChildren(current, node);
}
