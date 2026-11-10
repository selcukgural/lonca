export async function guarded(open, connect) {
  using file = open();
  await using connection = connect();
  return file.size + connection.id;
}
