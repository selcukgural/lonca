type Color = { r: number; g: number; b: number } | string;

export function palette() {
  return { red: "#f00", blue: { r: 0, g: 0, b: 255 } } satisfies Record<string, Color>;
}
