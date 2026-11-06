<?php
declare(strict_types=1);

namespace App\Models;

use Foo\Bar;
use Foo\Baz;

/** A client. */
#[Entity]
class Client extends Base {
    const LIMIT = 10;

    private int $total = 0;

    public function __construct(int $total) {
        $this->total = $total;
    }

    public function charge(int $amount): int {
        return $this->total + $amount + 1;
    }

    public function testCharge() {
        $this->assertTrue(true);
    }

    #[Test]
    public function later() {
        $this->markTestSkipped();
    }
}

interface Shape {
    public function area(): float;
}

enum Color: string {
    case Red = 'r';
    public function code() { return 1; }
}

function top($x) {
    return $x;
}
