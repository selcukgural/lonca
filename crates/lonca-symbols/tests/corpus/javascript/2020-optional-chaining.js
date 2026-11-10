export function city(user) {
  return user?.address?.["city"] ?? user?.fallback?.() ?? "unknown";
}
