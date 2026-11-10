<?php

function city(?object $user): ?string {
    return $user?->address?->city();
}
