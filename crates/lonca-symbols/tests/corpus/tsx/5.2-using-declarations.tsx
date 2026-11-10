export function Timed(props: { open: () => Disposable }) {
  using timer = props.open();
  return <span>done</span>;
}
