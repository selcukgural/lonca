<?php

#[Attribute(Attribute::TARGET_METHOD)]
class Route {
    public function __construct(public string $path) {}
}

class Pages {
    #[Route('/home')]
    public function home(): string {
        return 'home';
    }
}
