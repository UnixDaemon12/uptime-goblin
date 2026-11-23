# Generic configuration examples

These files are documentation examples using fictional endpoints. They contain no real credentials, no live data, and are not a backup. Uptime Goblin has no import endpoint.

- [global-settings.json](global-settings.json): complete nonsecret global defaults suitable as the shape of a `PATCH /api/settings` request; it intentionally omits email and sources.
- [linux-source.json](linux-source.json): source settings for `POST /api/services`. Replace the example exporter/destination URLs; monitoring starts disabled.
- [json-mappings.json](json-mappings.json): mapping array for an illustrative JSON response with `system.cpu` and `storage.freeBytes`.
- [prometheus-mappings.json](prometheus-mappings.json): mapping array for hypothetical exporter series. Confirm names and labels from your own exporter before use.

Use the source editor for ordinary setup. If using the API, authenticate over HTTPS and include `Content-Type: application/json` and `X-Goblin-Request: 1` on writes. Test first; a successful API settings save does not prove an endpoint or credential works.
