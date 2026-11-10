<?php

class Filters {
    public const UPPER = static function (string $s): string {
        return strtoupper($s);
    };

    public function apply(string $s): string {
        return (self::UPPER)($s);
    }
}
