class Base {
  run(): number {
    return 1;
  }
}

class Derived extends Base {
  override run(): number {
    return 2;
  }
}
