// Before 1.5, index.html loaded the whole web app from /app.js. The web app is now loaded by
// /boot.js from /assets/<build>/modules/, and this file remains only for a page from an earlier
// release (an open tab or a copy kept by a cache) that still asks for it: the loader moves that
// page to the current release.
import './boot.js';
