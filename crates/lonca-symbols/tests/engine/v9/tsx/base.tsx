import React from "react";

export function Price(props: { amount: number }) {
  return <span>{props.amount}</span>;
}

export function Gone() {
  return null;
}

export const Label = (p: { text: string }) => <b>{p.text}</b>;
