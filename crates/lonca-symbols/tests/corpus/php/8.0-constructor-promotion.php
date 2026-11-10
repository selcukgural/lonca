<?php

class Point {
    public function __construct(
        public int $x = 0,
        protected ?int $y = null,
    ) {}

    public function sum(): int {
        return $this->x + ($this->y ?? 0);
    }
}
