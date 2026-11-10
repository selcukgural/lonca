<?php

function slice(array $items): array {
    return array_slice(array: $items, offset: 1, preserve_keys: true);
}
