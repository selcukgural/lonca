<?php

class Service {
    public function __construct(private Logger $logger = new NullLogger()) {}

    public function ready(): bool {
        return true;
    }
}
