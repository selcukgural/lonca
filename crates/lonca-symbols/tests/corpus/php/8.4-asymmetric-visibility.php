<?php

class Counter {
    public private(set) int $count = 0;

    public function next(): int {
        return ++$this->count;
    }
}
