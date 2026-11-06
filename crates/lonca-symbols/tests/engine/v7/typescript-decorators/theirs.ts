export class C {
  @Listen('x')
  onX(): void {}

  @Input() f = 2;

  // section

  other(): void { go(); }
}
