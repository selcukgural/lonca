<?php

class Greeter {
    public function hello(): string {
        return 'hello';
    }
}

function greet(): string {
    return new Greeter()->hello();
}
