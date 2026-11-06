import React from "react";

export function Price(props: { amount: number }) {
  return <span>{props.amount}</span>;
}

export const Label = (p: { text: string; strong: boolean }) =>
  p.strong ? <b>{p.text}</b> : <i>{p.text}</i>;

export function Added() {
  return <hr />;
}
