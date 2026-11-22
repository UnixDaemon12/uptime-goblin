// Event handlers of the configuration page, and hash routing with Back and Forward protection.
import { exportConfiguration, exportHistory } from './exports.js';
import {
  navigate,
  renderConfiguration,
  renderRoute,
  renderSourceList,
  saveSettings,
} from './pages.js';
import { followMovedRoute } from './security.js';
import { loadSystem } from './system.js';
import { conflictMessage, replaceService, writeConfig } from '../core/api.js';
import { $, closeDialog, openDialog, toast } from '../core/dom.js';
import {
  allowDrawerLeave,
  allowPageLeave,
  drawerDirty,
  holdFocus,
  pageDirty,
  updateDirtyIndicator,
} from '../core/forms.js';
import { load } from '../core/load.js';
import { page } from '../core/page.js';
import { renderAlerts } from '../dashboard/dashboard.js';
import { loadDocumentation } from '../docs/docs.js';

let acceptedHash = location.hash,
  acceptedIndex = 0,
  restoringRoute = false;

/**
 * Registers this module’s event handlers (and, where noted, reads what the page needs at
 * start). main.js calls it once, keeping the order in which public/app.js registered them.
 */
export function install() {
  // A moved page's old address (1.4.x's #configure/security) opens where the page is now.
  acceptedHash = followMovedRoute();
  document.addEventListener('input', e => {
    if (e.target.closest('#configuration-content')) updateDirtyIndicator();
    if (e.target.id === 'source-search') renderSourceList();
  });
  document.addEventListener('change', e => {
    if (e.target.closest('#configuration-content')) updateDirtyIndicator();
    if (e.target.id === 'source-filter') renderSourceList();
  });
  document.addEventListener('click', async e => {
    // A link within the page ([data-in-page], such as "delivered" on the Notifications page)
    // is not a route: configure/notifications.js handles it.
    const routeLink = e.target.closest('a[href^="#"]:not([data-in-page])');
    if (routeLink && !e.metaKey && !e.ctrlKey && !e.shiftKey && !e.altKey && e.button === 0) {
      e.preventDefault();
      // A link to Help may name the guide it should open with (data-help), and one to the Audit
      // log the Kind it should open with (data-audit-kind: the System page's legacy Basic line).
      page.helpDoc = routeLink.dataset.help || null;
      page.auditKind = routeLink.dataset.auditKind ?? null;
      navigate(routeLink.getAttribute('href'));
      if (location.hash !== '#configure/help') page.helpDoc = null;
      if (location.hash !== '#configure/audit') page.auditKind = null;
      return;
    }
    if (e.target.closest('[data-discard]')) {
      if (allowPageLeave()) renderConfiguration();
      return;
    }
    const hidden = e.target.closest('[data-visibility]');
    if (hidden) {
      const source = page.data.config.services.find(s => s.id === hidden.dataset.visibility);
      // The button is disabled until its write is answered, which drops its focus to <body>:
      // holdFocus() keeps it, through a sign-in dialog the write may open too (Cancel returns
      // there), and gives it back at the end. The list is patched in place, so after a
      // success it is the same button, now saying Show or Hide the other way round.
      const release = holdFocus(hidden);
      hidden.disabled = true;
      try {
        await writeConfig(
          '/api/services/' + encodeURIComponent(source.id),
          {
            method: 'PATCH',
            body: JSON.stringify({ showOnDashboard: source.showOnDashboard === false }),
          },
          { revision: () => page.data.config.revision, apply: replaceService, source: source.id }
        );
        await load();
        toast(
          source.showOnDashboard === false
            ? 'Source shown on the dashboard.'
            : 'Source hidden. Monitoring continues.'
        );
      } catch (error) {
        toast(
          error.status === 409
            ? `${conflictMessage} The latest settings are shown now.`
            : error.message
        );
        hidden.disabled = false;
        if (error.status === 409) await load();
      } finally {
        release();
      }
      return;
    }
    if (e.target.closest('[data-view-alerts]')) {
      renderAlerts();
      openDialog($('#alerts-dialog'));
      return;
    }
    const doc = e.target.closest('[data-doc]');
    if (doc) {
      await loadDocumentation(doc.dataset.doc);
      return;
    }
    if (e.target.closest('#refresh-system')) {
      await loadSystem();
      return;
    }
    const configExport = e.target.closest('#export-config');
    if (configExport) {
      await exportConfiguration(configExport);
      return;
    }
    const historyExport = e.target.closest('[data-export-history]');
    if (historyExport) {
      await exportHistory(historyExport.dataset.exportHistory, page.range, historyExport);
      return;
    }
    const exportButton = e.target.closest('#export-history');
    if (exportButton)
      await exportHistory($('#export-source').value, $('#export-range').value, exportButton);
  });
  document.addEventListener('submit', async e => {
    if (e.target.id === 'settings-form') {
      e.preventDefault();
      await saveSettings(e.target);
    }
    // The × buttons close their dialog with the same exit motion as a click outside.
    if (e.target.matches('dialog > .dialog-heading')) {
      e.preventDefault();
      const dialog = e.target.parentElement;
      if (dialog.id !== 'settings-dialog' || allowDrawerLeave()) closeDialog(dialog);
    }
  });
  // Escape is handled here: Chromium ignores preventDefault() on the 'cancel' event of a
  // second Escape without user activation in between, which would close a drawer the user
  // chose to keep. Cancelling the keydown stops that close request altogether. (On the
  // document, because focus can sit on <body> while the modal drawer is open.)
  document.addEventListener('keydown', e => {
    if (e.key !== 'Escape' || e.isComposing || e.defaultPrevented) return;
    // The sign-in dialog opens over everything else and handles its own Escape (Cancel); the
    // drawer under it stays open with its draft (see identity/session.js).
    if ($('#signin-dialog').open) return;
    // The alerts dialog sits above the drawer when both are open, so it closes first.
    if ($('#alerts-dialog').open) {
      e.preventDefault();
      closeDialog($('#alerts-dialog'));
      return;
    }
    if (!$('#settings-dialog').open) return;
    e.preventDefault();
    if (allowDrawerLeave()) closeDialog($('#settings-dialog'));
  });
  // Other close requests (such as a phone's back gesture) take the same path as Escape.
  $('#settings-dialog').addEventListener('cancel', e => {
    e.preventDefault();
    if (allowDrawerLeave()) closeDialog($('#settings-dialog'));
  });
  $('#alerts-dialog').addEventListener('cancel', e => {
    e.preventDefault();
    closeDialog($('#alerts-dialog'));
  });
  // A click on the dimmed area outside a dialog closes it, like Escape; unsaved drawer edits
  // still ask first. Only a press that starts and ends outside counts, so selecting text
  // inside and releasing outside closes nothing. Clicks on the backdrop reach the <dialog>
  // element itself, outside its box; clicks inside land on its content or padding.
  let pressedOutside = null;
  const outsideOf = (dialog, e) => {
    if (e.target !== dialog) return false;
    const box = dialog.getBoundingClientRect();
    return (
      e.clientX < box.left || e.clientX > box.right || e.clientY < box.top || e.clientY > box.bottom
    );
  };
  for (const dialog of [$('#settings-dialog'), $('#alerts-dialog')]) {
    dialog.addEventListener('pointerdown', e => {
      pressedOutside = outsideOf(dialog, e) ? dialog : null;
    });
    dialog.addEventListener('click', e => {
      const outside = pressedOutside === dialog && outsideOf(dialog, e);
      pressedOutside = null;
      if (!outside) return;
      if (dialog.id === 'settings-dialog' && !allowDrawerLeave()) return;
      closeDialog(dialog);
    });
  }
  $('#settings-dialog').addEventListener('close', () => {
    if ($('#settings-dialog').open) return;
    page.drawerBaseline = '';
    document.body.append($('#toast'));
  });
  // Each accepted route records its position in history.state, so a refused Back or Forward
  // can return to the entry the user was on instead of overwriting the one they left for.
  if (Number.isInteger(history.state?.orbitIndex)) acceptedIndex = history.state.orbitIndex;
  else history.replaceState({ orbitIndex: acceptedIndex }, '');
  window.addEventListener('hashchange', () => {
    followMovedRoute();
    const index = history.state?.orbitIndex;
    if (restoringRoute && location.hash === acceptedHash) {
      restoringRoute = false;
      return;
    }
    restoringRoute = false;
    if (!allowPageLeave() || ($('#settings-dialog').open && !allowDrawerLeave())) {
      // A new entry (link or typed URL) sits just after the accepted one.
      const delta = acceptedIndex - (Number.isInteger(index) ? index : acceptedIndex + 1);
      if (delta) {
        restoringRoute = true;
        history.go(delta);
      } else
        history.replaceState(
          { orbitIndex: acceptedIndex },
          '',
          location.pathname + location.search + acceptedHash
        );
      return;
    }
    if (Number.isInteger(index)) acceptedIndex = index;
    else history.replaceState({ orbitIndex: ++acceptedIndex }, '');
    acceptedHash = location.hash;
    page.pageBaseline = '';
    page.drawerBaseline = '';
    closeDialog($('#settings-dialog'));
    // The alerts dialog's View deliveries leads to another page, which it would cover. It
    // closes at once: during an exit motion the page stays inert, so renderRoute() could not
    // focus the new page's title, and the dialog would then give the focus back to the alerts
    // button on the dashboard just hidden, leaving it on <body>.
    closeDialog($('#alerts-dialog'), { now: true });
    if (page.data) renderRoute();
  });
  window.addEventListener('beforeunload', e => {
    // Kiosk updates deliberately discard drafts; an unattended display cannot answer a
    // leave-page prompt. Signing out asked already. Ordinary navigation and reloads still
    // protect unsaved edits.
    if (page.kioskUpdateReloading || page.signingOut) return;
    if (pageDirty() || drawerDirty() || page.busyForm) {
      e.preventDefault();
      e.returnValue = '';
    }
  });
  $('#configuration-nav').addEventListener('keydown', e => {
    const links = [...$('#configuration-nav').querySelectorAll('a')],
      index = links.indexOf(e.target);
    if (index < 0) return;
    let next;
    if (e.key === 'ArrowDown' || e.key === 'ArrowRight') next = (index + 1) % links.length;
    else if (e.key === 'ArrowUp' || e.key === 'ArrowLeft')
      next = (index - 1 + links.length) % links.length;
    else if (e.key === 'Home') next = 0;
    else if (e.key === 'End') next = links.length - 1;
    else return;
    e.preventDefault();
    links[next].focus();
  });
}
