<?php

function total(Countable&Traversable $items): never {
    throw new LogicException((string) count($items));
}
