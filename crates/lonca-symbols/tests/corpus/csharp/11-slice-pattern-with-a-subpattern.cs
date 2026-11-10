public static class Slices
{
    public static int Rest(int[] xs) => xs is [_, .. var rest] ? rest.Length : 0;
}
