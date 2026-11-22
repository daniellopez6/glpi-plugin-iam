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

use GlpiPlugin\Iam\Ownership;
use PHPUnit\Framework\TestCase;

final class OwnershipTest extends TestCase
{
    private const T = 'glpi_plugin_iam_resources';

    public function testOwnerByUser(): void
    {
        $res = ['users_id_owner' => 7, 'groups_id_owner' => 0];
        $this->assertTrue(Ownership::isOwner($res, 7, []));
        $this->assertFalse(Ownership::isOwner($res, 8, []));
    }

    public function testOwnerByGroupMembership(): void
    {
        $res = ['users_id_owner' => 0, 'groups_id_owner' => 5];
        $this->assertTrue(Ownership::isOwner($res, 9, [3, 5]));
        $this->assertTrue(Ownership::isOwner($res, 9, ['5']));
    }

    public function testGroupChangeRevokesOwnership(): void
    {
        $res = ['users_id_owner' => 0, 'groups_id_owner' => 5];
        $this->assertTrue(Ownership::isOwner($res, 9, [5]));
        $this->assertFalse(Ownership::isOwner($res, 9, [3]));
    }

    public function testAnonymousOwnsNothing(): void
    {
        $this->assertFalse(Ownership::isOwner(['users_id_owner' => 0, 'groups_id_owner' => 0], 0, [0]));
        $this->assertFalse(Ownership::isOwner(['users_id_owner' => 0, 'groups_id_owner' => 5], 0, [5]));
        $this->assertSame([self::T . '.id' => 0], Ownership::resourceCriteria(0, [5], self::T));
    }

    public function testUnownedResourceMatchesNobody(): void
    {
        $res = ['users_id_owner' => 0, 'groups_id_owner' => 0];
        $this->assertFalse(Ownership::isOwner($res, 4, [0, 1]));
        $this->assertFalse(Ownership::isOwner([], 4, [1]));
    }

    public function testCriteriaWithGroups(): void
    {
        $this->assertSame(
            ['OR' => [
                self::T . '.users_id_owner'  => 4,
                self::T . '.groups_id_owner' => [1, 2],
            ]],
            Ownership::resourceCriteria(4, [1, '2', 0, 1], self::T)
        );
    }

    public function testCriteriaWithoutGroups(): void
    {
        $c = Ownership::resourceCriteria(4, [], self::T);
        $this->assertSame(['OR' => [self::T . '.users_id_owner' => 4]], $c);
        $this->assertArrayNotHasKey(self::T . '.groups_id_owner', $c['OR']);
        $c = Ownership::resourceCriteria(4, [0], self::T);
        $this->assertArrayNotHasKey(self::T . '.groups_id_owner', $c['OR']);
    }
}
