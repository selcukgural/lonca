<?php

class Limits {
    public const int MAX = 10;
    final protected const string NAME = 'limits';

    public function max(string $name): int {
        return self::{$name};
    }
}
