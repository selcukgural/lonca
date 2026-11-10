export class Account {
  #balance = 0;

  static #check(amount) {
    return amount > 0;
  }

  get #doubled() {
    return this.#balance * 2;
  }

  deposit(amount) {
    if (Account.#check(amount)) this.#balance += amount;
    return this.#doubled;
  }

  static is(value) {
    return #balance in value;
  }
}
