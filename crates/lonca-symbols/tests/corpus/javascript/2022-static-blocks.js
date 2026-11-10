export class Registry {
  static items;

  static {
    Registry.items = new Map();
  }

  static size() {
    return Registry.items.size;
  }
}
