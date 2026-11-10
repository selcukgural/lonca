export function defaults(options) {
  options.retries ??= 3;
  options.verbose ||= false;
  options.name &&= options.name.trim();
  return options;
}
