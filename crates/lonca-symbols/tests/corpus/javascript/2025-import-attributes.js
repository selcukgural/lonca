import data from "./data.json" with { type: "json" };

export function count() {
  return data.length;
}
