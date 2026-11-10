<?php

function first((Countable&Traversable)|null $items): true|null {
    return $items === null ? null : true;
}
