<?php

class User {
    public readonly string $name;

    public function __construct(string $name) {
        $this->name = $name;
    }
}
