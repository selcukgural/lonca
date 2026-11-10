<?php

class Person {
    public string $name {
        get => ucfirst($this->name);
        set(string $value) {
            $this->name = trim($value);
        }
    }

    public function greet(): string {
        return 'hello ' . $this->name;
    }
}
