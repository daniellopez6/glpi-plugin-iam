<?php

/**
 * -------------------------------------------------------------------------
 * IAM - Identity & Access Governance plugin for GLPI
 * Copyright (C) 2026 daniellopez6
 * https://github.com/daniellopez6/glpi-plugin-iam
 * -------------------------------------------------------------------------
 * LICENSE
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version. See LICENSE for the full text.
 * -------------------------------------------------------------------------
 */

namespace GlpiPlugin\Iam\Tests\Unit;

use GlpiPlugin\Iam\PositionScope;
use PHPUnit\Framework\TestCase;

final class PositionScopeTest extends TestCase
{
    public function testSameEntityAllowed(): void
    {
        $this->assertTrue(PositionScope::parentAllowed(1, false, 1, [0]));
    }

    public function testRecursiveAncestorAllowed(): void
    {
        $this->assertTrue(PositionScope::parentAllowed(0, true, 1, [0]));
        $this->assertTrue(PositionScope::parentAllowed(1, true, 3, ['0', '1']));
    }

    public function testNonRecursiveAncestorRefused(): void
    {
        $this->assertFalse(PositionScope::parentAllowed(0, false, 1, [0]));
    }

    public function testUnrelatedOrDescendantEntityRefused(): void
    {
        $this->assertFalse(PositionScope::parentAllowed(2, true, 1, [0]));
        $this->assertFalse(PositionScope::parentAllowed(3, true, 1, [0]));
    }
}
