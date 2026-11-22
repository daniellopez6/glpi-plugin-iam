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

use GlpiPlugin\Iam\PersonVisibility;
use PHPUnit\Framework\TestCase;

final class PersonVisibilityTest extends TestCase
{
    public function testPersonWithAuthorisationsFollowsTheEntities(): void
    {
        foreach ([true, false] as $readAll) {
            foreach ([true, false] as $anchor) {
                $this->assertTrue(PersonVisibility::visible(true, true, $readAll, $anchor));
                // authorisations only in entities the session cannot see: hidden, whatever the anchor
                $this->assertFalse(PersonVisibility::visible(true, false, $readAll, $anchor));
            }
        }
    }

    public function testLeaverVisibleOnlyToWholeRegisterReadersWithAVisibleAnchor(): void
    {
        $this->assertTrue(PersonVisibility::visible(false, false, true, true));
        $this->assertFalse(PersonVisibility::visible(false, false, true, false));
        $this->assertFalse(PersonVisibility::visible(false, false, false, true));
        $this->assertFalse(PersonVisibility::visible(false, false, false, false));
    }
}
