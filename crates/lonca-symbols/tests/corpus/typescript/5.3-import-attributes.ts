import config from "./config.json" with { type: "json" };

export function name(): string {
  return config.name;
}
