import labels from "./labels.json" with { type: "json" };

export function Label() {
  return <label>{labels.name}</label>;
}
