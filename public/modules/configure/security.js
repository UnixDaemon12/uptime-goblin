// The Security page of 1.4.x: its password change moved to the Account page in 1.5 (see
// identity/account.js). Its address, #configure/security, stays in bookmarks, older guides
// and browser history, so it opens the Account page instead of the Overview.
const moved = Object.freeze({ '#configure/security': '#configure/account' });

/**
 * Replaces the current history entry's address with the current one of a moved page, keeping
 * the entry's state (its position, see configure/events.js). Returns the address now shown.
 */
export function followMovedRoute() {
  const target = moved[location.hash];
  if (target) history.replaceState(history.state, '', location.pathname + location.search + target);
  return location.hash;
}
