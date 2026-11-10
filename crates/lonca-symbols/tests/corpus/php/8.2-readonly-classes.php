<?php

readonly class Money {
    public function __construct(public int $amount, public string $currency) {}

    public function isZero(): bool {
        return $this->amount === 0;
    }
}
