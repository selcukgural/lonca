type Props = { title: string };

export function Title(props: Props) {
  const style = { color: "red" } satisfies Record<string, string>;
  return <h1 style={style}>{props.title}</h1>;
}
