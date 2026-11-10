import defer * as heavy from "./heavy.js";

export function run(): number {
  return heavy.compute();
}
