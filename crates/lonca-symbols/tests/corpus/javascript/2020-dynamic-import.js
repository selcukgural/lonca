export async function load(name) {
  const module = await import(`./plugins/${name}.js`);
  return module.default ?? import.meta.url;
}
