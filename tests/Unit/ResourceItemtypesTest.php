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

use GlpiPlugin\Iam\ResourceItemtypes;
use PHPUnit\Framework\TestCase;

final class ResourceItemtypesTest extends TestCase
{
    public function testAcceptsSoftware(): void
    {
        $this->assertTrue(ResourceItemtypes::isAllowed('Software'));
        foreach (ResourceItemtypes::ALLOWED as $type) {
            $this->assertTrue(ResourceItemtypes::isAllowed($type));
        }
    }

    public function testRejectsUnknownItemtype(): void
    {
        foreach (['User', 'Glpi\\Foo', 'software', 'SOFTWARE', '', 'Software ', 'Computer;'] as $type) {
            $this->assertFalse(ResourceItemtypes::isAllowed($type), $type);
        }
    }

    public function testExactList(): void
    {
        $this->assertSame(
            ['Software', 'Appliance', 'Computer', 'NetworkEquipment', 'Database', 'DatabaseInstance',
             'Domain', 'Certificate', 'Supplier'],
            ResourceItemtypes::ALLOWED
        );
    }
}
