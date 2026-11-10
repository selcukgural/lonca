<?php

function label(int $code): string {
    return match (true) {
        $code < 300 => 'ok',
        $code === 404, $code === 410 => 'gone',
        default => 'error',
    };
}
