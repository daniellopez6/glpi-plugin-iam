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

use GlpiPlugin\Iam\GroupMembership;
use PHPUnit\Framework\TestCase;

final class GroupMembershipTest extends TestCase
{
    /** Tree: 1 > 2 (recursive) > 3; 1 > 4 (not recursive) > 5; 6 alone */
    private const GROUPS = [
        ['id' => 2, 'groups_id' => 1, 'recursive_membership' => 1],
        ['id' => 3, 'groups_id' => 2, 'recursive_membership' => 0],
        ['id' => 4, 'groups_id' => 1, 'recursive_membership' => 0],
        ['id' => 5, 'groups_id' => 4, 'recursive_membership' => 0],
        ['id' => 6, 'groups_id' => 0, 'recursive_membership' => 0],
    ];

    private function sorted(array $ids): array
    {
        sort($ids);
        return $ids;
    }

    public function testDirectGroupsOnlyWithoutRecursiveMembership(): void
    {
        $this->assertSame([1, 6], $this->sorted(GroupMembership::expand(
            [['groups_id' => '1', 'recursive_membership' => 0], ['groups_id' => 6, 'recursive_membership' => null]],
            self::GROUPS
        )));
    }

    public function testRecursiveMembershipAddsChildrenAndStopsAtNonRecursiveChild(): void
    {
        // 1 recursive: children 2 and 4; 2 recursive: its child 3; 4 not recursive: 5 is not added
        $this->assertSame([1, 2, 3, 4], $this->sorted(GroupMembership::expand([['groups_id' => 1, 'recursive_membership' => 1]], self::GROUPS)));
    }

    public function testNoMembershipNoGroups(): void
    {
        $this->assertSame([], GroupMembership::expand([], self::GROUPS));
        $this->assertSame([], GroupMembership::expand([['groups_id' => 0, 'recursive_membership' => 1]], self::GROUPS));
    }

    public function testCycleDoesNotLoopAndDuplicatesAreRemoved(): void
    {
        $cycle = [['id' => 8, 'groups_id' => 7, 'recursive_membership' => 1], ['id' => 7, 'groups_id' => 8, 'recursive_membership' => 1]];
        $this->assertSame([7, 8], $this->sorted(GroupMembership::expand(
            [['groups_id' => 7, 'recursive_membership' => 1], ['groups_id' => 8, 'recursive_membership' => 1]],
            $cycle
        )));
    }
}
