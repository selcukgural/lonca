<?php

function slug(string $title): string {
    return $title |> trim(...) |> strtolower(...) |> (fn($s) => str_replace(' ', '-', $s));
}
