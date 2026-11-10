export function greekLetters(text) {
  return text.match(/[\p{Script=Greek}&&\p{Letter}]/gv) ?? [];
}
