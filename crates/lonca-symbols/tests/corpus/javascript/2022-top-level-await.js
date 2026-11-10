const response = await fetch("https://example.com/config.json");

export function ok() {
  return response.ok;
}
