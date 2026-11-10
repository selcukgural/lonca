export function Options<const T extends readonly string[]>(props: { items: T }) {
  return (
    <ul>
      {props.items.map((item) => (
        <li key={item}>{item}</li>
      ))}
    </ul>
  );
}
