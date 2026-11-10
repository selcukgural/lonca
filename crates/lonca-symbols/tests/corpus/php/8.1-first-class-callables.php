<?php

function lengths(array $words): array {
    return array_map(strlen(...), $words);
}
