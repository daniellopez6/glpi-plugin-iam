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

use GlpiPlugin\Iam\FieldSets;
use GlpiPlugin\Iam\InputGuard;
use PHPUnit\Framework\TestCase;

final class InputGuardTest extends TestCase
{
    public function testDropsUnknownFields(): void
    {
        $out = InputGuard::filter(['name' => 'a', 'evil' => 1, 'id' => 5], ['name'], [], false);
        $this->assertSame(['name' => 'a'], $out);
    }

    public function testDropsImmutableOnUpdate(): void
    {
        $in = ['users_id' => 3, 'plugin_iam_roles_id' => 4, 'entities_id' => 2, 'comment' => 'x'];
        $allowed = ['users_id', 'plugin_iam_roles_id', 'entities_id', 'comment'];
        $immutable = ['users_id', 'plugin_iam_roles_id', 'entities_id'];

        $this->assertSame(['comment' => 'x'], InputGuard::filter($in, $allowed, $immutable, true));
        $this->assertSame($in, InputGuard::filter($in, $allowed, $immutable, false));
    }

    public function testEnumRejectsUnknownLevel(): void
    {
        $levels = ['standard', 'sensitive', 'privileged'];
        $this->assertFalse(InputGuard::enum('admin', $levels));
        $this->assertFalse(InputGuard::enum('', $levels));
        $this->assertFalse(InputGuard::enum('Standard', $levels));
        $this->assertTrue(InputGuard::enum('privileged', $levels));
    }

    public function testWhitelistsNeverAcceptStateOrAuditFields(): void
    {
        foreach ([FieldSets::RESOURCE, FieldSets::ROLE] as $fields) {
            foreach (['id', 'is_deleted', 'date_mod', 'date_creation'] as $forbidden) {
                $this->assertNotContains($forbidden, $fields);
            }
        }
        $in = ['name' => 'x', 'is_deleted' => 1, 'date_mod' => '2000-01-01', 'id' => 9];
        $this->assertSame(['name' => 'x'], InputGuard::filter($in, FieldSets::RESOURCE, FieldSets::RESOURCE_IMMUTABLE, false));
    }

    public function testRoleResourceAndEntityAreImmutable(): void
    {
        $in = ['plugin_iam_resources_id' => 2, 'entities_id' => 3, 'name' => 'n'];
        $this->assertSame(['name' => 'n'], InputGuard::filter($in, FieldSets::ROLE, FieldSets::ROLE_IMMUTABLE, true));
    }

    public function testExpectationValues(): void
    {
        $values = ['allowed', 'on_request', 'forbidden'];
        foreach ($values as $v) {
            $this->assertTrue(InputGuard::enum($v, $values));
        }
        $this->assertFalse(InputGuard::enum('yes', $values));
        $this->assertSame(['expectation' => 'allowed'], InputGuard::filter(
            ['expectation' => 'allowed', 'plugin_iam_positions_id' => 1, 'entities_id' => 5, 'is_deleted' => 1],
            FieldSets::POSITION_ROLE,
            FieldSets::POSITION_ROLE_IMMUTABLE,
            true
        ));
    }
}
