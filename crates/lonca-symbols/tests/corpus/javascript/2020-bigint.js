export function factorial(n) {
  return n <= 1n ? 1n : n * factorial(n - 1n);
}
