<?php

enum Suit: string {
    case Hearts = 'h';
    case Spades = 's';

    const Wild = self::Spades;

    public function color(): string {
        return match ($this) {
            self::Hearts => 'red',
            self::Spades => 'black',
        };
    }
}
