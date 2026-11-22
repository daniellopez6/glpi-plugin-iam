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

use GlpiPlugin\Iam\MatrixBuilder;
use PHPUnit\Framework\TestCase;

/** The "No active position" bucket: held grants of people without any active position. */
final class MatrixWithoutPositionTest extends TestCase
{
    private const TODAY = '2026-11-22';

    /** @return list<array<string,mixed>> */
    private static function roles(): array
    {
        return [
            ['id' => 30, 'name' => 'reader', 'level' => 'standard', 'plugin_iam_resources_id' => 5, 'resource_name' => 'ERP'],
            ['id' => 31, 'name' => 'admin', 'level' => 'privileged', 'plugin_iam_resources_id' => 5, 'resource_name' => 'ERP'],
        ];
    }

    /** @return array<string,mixed> */
    private static function grant(int $id, int $user, int $role = 30, string $status = 'active'): array
    {
        return ['id' => $id, 'users_id' => $user, 'plugin_iam_roles_id' => $role, 'status' => $status];
    }

    /** @return array<string,mixed> */
    private static function assignment(int $user, ?string $end = null, string $begin = '2026-01-01'): array
    {
        return ['plugin_iam_positions_id' => 1, 'users_id' => $user, 'date_begin' => $begin, 'date_end' => $end];
    }

    public function testPersonWithoutAnyAssignmentIsUnexpected(): void
    {
        $w = MatrixBuilder::withoutPosition(self::roles(), [], [self::grant(90, 7)], self::TODAY);
        $this->assertSame(['expectation' => null, 'ok' => 0, 'expected' => 0, 'unexpected' => 1, 'forbidden_held' => 0], $w['cells']['0:30']);
        $this->assertSame([['users_id' => 7, 'state' => 'unexpected', 'grants_id' => 90]], $w['holders']['0:30']);
    }

    public function testEndedAndFutureAssignmentsDoNotCount(): void
    {
        $w = MatrixBuilder::withoutPosition(
            self::roles(),
            [self::assignment(7, '2026-08-31'), self::assignment(8, null, '2026-12-01')],
            [self::grant(90, 7), self::grant(91, 8)],
            self::TODAY
        );
        $this->assertSame([7, 8], array_column($w['holders']['0:30'], 'users_id'));
        $this->assertSame(2, $w['cells']['0:30']['unexpected']);
    }

    public function testPersonWithActivePositionIsNotInTheBucket(): void
    {
        // Even when the position has no expectation on the role: that is an "unexpected" of the position row
        $w = MatrixBuilder::withoutPosition(self::roles(), [self::assignment(7)], [self::grant(90, 7)], self::TODAY);
        $this->assertSame([], $w['cells']);
        $this->assertSame([], $w['holders']);
    }

    public function testOnlyHeldGrantsOnColumnRoles(): void
    {
        $w = MatrixBuilder::withoutPosition(
            self::roles(),
            [],
            [self::grant(90, 7, 30, 'revoked'), self::grant(91, 7, 30, 'pending'), self::grant(92, 7, 30, 'expired'), self::grant(93, 7, 999),
                self::grant(94, 8, 31, 'revoke_pending'), self::grant(95, 9, 31, 'modify_pending')],
            self::TODAY
        );
        $this->assertArrayNotHasKey('0:30', $w['cells']);
        $this->assertArrayNotHasKey('0:999', $w['cells']);
        $this->assertSame([8, 9], array_column($w['holders']['0:31'], 'users_id'));
    }

    public function testOneEntryPerPersonAndRoleWithLowestGrantId(): void
    {
        $w = MatrixBuilder::withoutPosition(self::roles(), [], [self::grant(95, 7), self::grant(90, 7), self::grant(80, 3)], self::TODAY);
        $this->assertSame(
            [['users_id' => 3, 'state' => 'unexpected', 'grants_id' => 80], ['users_id' => 7, 'state' => 'unexpected', 'grants_id' => 90]],
            $w['holders']['0:30']
        );
        $this->assertSame(2, $w['cells']['0:30']['unexpected']);
    }
}
