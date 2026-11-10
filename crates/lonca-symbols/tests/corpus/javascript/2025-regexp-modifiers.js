export function sameDay(text) {
  return /(?i:mon)day|(?<year>\d{4})-\d\d|\d\d-(?<year>\d{4})/.test(text);
}
