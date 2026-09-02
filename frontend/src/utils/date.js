/**
 * Backend timestamps are stored and serialized as naive UTC strings with no
 * timezone marker (e.g. "2026-09-02T07:04:57"). JavaScript's Date parser
 * treats a marker-less ISO string as LOCAL time, not UTC, which silently
 * shifts every displayed time by the browser's UTC offset. This wrapper
 * appends "Z" before parsing (unless the string already has a timezone
 * marker) so every displayed timestamp is correctly converted from UTC to
 * the viewer's local time.
 */
export function parseUtc(dateStr) {
  if (!dateStr) return null;
  if (/Z$|[+-]\d{2}:\d{2}$/.test(dateStr)) {
    return new Date(dateStr);
  }
  return new Date(dateStr + "Z");
}