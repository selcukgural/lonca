import { type Stats, statSync } from "node:fs";

export function size(path: string): Stats["size"] {
  return statSync(path).size;
}
