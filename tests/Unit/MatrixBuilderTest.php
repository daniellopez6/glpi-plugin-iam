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

final class MatrixBuilderTest extends TestCase
{
    private const TODAY = '2026-11-22';
    private const USER = 7;
    private const ROLE = 30;

    /** @return list<array<string,mixed>> */
    private static function positions(int ...$ids): array
    {
        return array_map(static fn (int $id): array => ['id' => $id, 'name' => "P$id", 'area' => 'IT'], $ids);
    }

    /** @return list<array<string,mixed>> */
    private static function roles(): array
    {
        return [['id' => self::ROLE, 'name' => 'reader', 'level' => 'standard', 'plugin_iam_resources_id' => 5, 'resource_name' => 'ERP']];
    }

    /** @return array<string,mixed> */
    private static function cell(int $pos, string $expectation, int $role = self::ROLE): array
    {
        return ['plugin_iam_positions_id' => $pos, 'plugin_iam_roles_id' => $role, 'expectation' => $expectation];
    }

    /** @return array<string,mixed> */
    private static function assignment(int $pos, ?string $end = null, int $user = self::USER): array
    {
        return ['plugin_iam_positions_id' => $pos, 'users_id' => $user, 'date_begin' => '2026-01-01', 'date_end' => $end];
    }

    /** @return array<string,mixed> */
    private static function grant(int $id, string $status = 'active', int $user = self::USER, int $role = self::ROLE): array
    {
        return ['id' => $id, 'users_id' => $user, 'plugin_iam_roles_id' => $role, 'status' => $status];
    }

    /**
     * @param array<string,mixed> $model
     * @return list<string>
     */
    private static function states(array $model, string $key): array
    {
        return array_map(static fn (array $h): string => $h['state'], $model['holders'][$key] ?? []);
    }

    public function testShape(): void
    {
        $m = MatrixBuilder::build(self::positions(1), self::roles(), [self::cell(1, 'allowed')], [self::assignment(1)], [self::grant(90)], self::TODAY);
        $this->assertSame([['id' => 1, 'name' => 'P1', 'area' => 'IT']], $m['rows']);
        $this->assertSame([['resource_id' => 5, 'resource' => 'ERP', 'roles' => [['id' => self::ROLE, 'name' => 'reader', 'level' => 'standard']]]], $m['cols']);
        $this->assertSame(['expectation' => 'allowed', 'ok' => 1, 'expected' => 1, 'unexpected' => 0, 'forbidden_held' => 0], $m['cells']['1:30']);
        $this->assertSame([['users_id' => self::USER, 'state' => 'ok', 'grants_id' => 90]], $m['holders']['1:30']);
    }

    public function testAllowedAndHeldIsOk(): void
    {
        $m = MatrixBuilder::build(self::positions(1), self::roles(), [self::cell(1, 'allowed')], [self::assignment(1)], [self::grant(90)], self::TODAY);
        $this->assertSame(1, $m['cells']['1:30']['ok']);
        $this->assertSame(0, $m['cells']['1:30']['unexpected']);
        $this->assertSame(['ok'], self::states($m, '1:30'));
    }

    public function testOnRequestHeldIsOkAndNeverMissing(): void
    {
        $held = MatrixBuilder::build(self::positions(1), self::roles(), [self::cell(1, 'on_request')], [self::assignment(1)], [self::grant(90)], self::TODAY);
        $this->assertSame(1, $held['cells']['1:30']['ok']);
        $this->assertSame(0, $held['cells']['1:30']['expected']);
        $this->assertSame(['ok'], self::states($held, '1:30'));

        $absent = MatrixBuilder::build(self::positions(1), self::roles(), [self::cell(1, 'on_request')], [self::assignment(1)], [], self::TODAY);
        $this->assertSame([], self::states($absent, '1:30'));
        $this->assertSame(0, $absent['cells']['1:30']['ok']);
    }

    public function testMissingExpectedGrant(): void
    {
        $m = MatrixBuilder::build(self::positions(1), self::roles(), [self::cell(1, 'allowed')], [self::assignment(1)], [], self::TODAY);
        $this->assertSame(1, $m['cells']['1:30']['expected']);
        $this->assertSame(0, $m['cells']['1:30']['ok']);
        $this->assertSame([['users_id' => self::USER, 'state' => 'missing', 'grants_id' => null]], $m['holders']['1:30']);
    }

    public function testUnexpectedGrant(): void
    {
        $m = MatrixBuilder::build(self::positions(1), self::roles(), [], [self::assignment(1)], [self::grant(90)], self::TODAY);
        $this->assertSame(['expectation' => null, 'ok' => 0, 'expected' => 0, 'unexpected' => 1, 'forbidden_held' => 0], $m['cells']['1:30']);
        $this->assertSame([['users_id' => self::USER, 'state' => 'unexpected', 'grants_id' => 90]], $m['holders']['1:30']);
    }

    public function testSecondActivePositionJustifiesGrant(): void
    {
        $m = MatrixBuilder::build(
            self::positions(1, 2),
            self::roles(),
            [self::cell(2, 'allowed')],
            [self::assignment(1), self::assignment(2)],
            [self::grant(90)],
            self::TODAY
        );
        $this->assertSame(0, $m['cells']['1:30']['unexpected'] ?? 0);
        $this->assertNotContains('unexpected', self::states($m, '1:30'));
        $this->assertSame(1, $m['cells']['2:30']['ok']);
    }

    public function testEndedPositionDoesNotJustify(): void
    {
        $m = MatrixBuilder::build(
            self::positions(1, 2),
            self::roles(),
            [self::cell(2, 'allowed')],
            [self::assignment(1), self::assignment(2, '2026-11-21')],
            [self::grant(90)],
            self::TODAY
        );
        $this->assertSame(1, $m['cells']['1:30']['unexpected']);
        $this->assertSame(['unexpected'], self::states($m, '1:30'));
        // The ended position no longer counts the person: nobody expected, nobody holding in that row
        $this->assertSame(0, $m['cells']['2:30']['expected']);
        $this->assertSame(0, $m['cells']['2:30']['ok']);
        $this->assertSame([], self::states($m, '2:30'));
    }

    public function testFutureAssignmentDoesNotCount(): void
    {
        $future = ['plugin_iam_positions_id' => 1, 'users_id' => self::USER, 'date_begin' => '2026-12-01', 'date_end' => null];
        $m = MatrixBuilder::build(self::positions(1), self::roles(), [self::cell(1, 'allowed')], [$future], [], self::TODAY);
        $this->assertSame(0, $m['cells']['1:30']['expected']);
        $this->assertSame([], self::states($m, '1:30'));
    }

    public function testForbiddenHeld(): void
    {
        $m = MatrixBuilder::build(self::positions(1), self::roles(), [self::cell(1, 'forbidden')], [self::assignment(1)], [self::grant(90)], self::TODAY);
        $this->assertSame(1, $m['cells']['1:30']['forbidden_held']);
        $this->assertSame(0, $m['cells']['1:30']['ok']);
        $this->assertSame(0, $m['cells']['1:30']['unexpected']);
        $this->assertSame([['users_id' => self::USER, 'state' => 'forbidden_held', 'grants_id' => 90]], $m['holders']['1:30']);
    }

    public function testForbiddenHeldButAllowedByAnotherActivePosition(): void
    {
        $m = MatrixBuilder::build(
            self::positions(1, 2),
            self::roles(),
            [self::cell(1, 'forbidden'), self::cell(2, 'allowed')],
            [self::assignment(1), self::assignment(2)],
            [self::grant(90)],
            self::TODAY
        );
        $this->assertSame(0, $m['cells']['1:30']['forbidden_held']);
        $this->assertSame(1, $m['cells']['2:30']['ok']);
    }

    public function testRevokedGrantIgnored(): void
    {
        $m = MatrixBuilder::build(self::positions(1), self::roles(), [self::cell(1, 'allowed')], [self::assignment(1)], [self::grant(90, 'revoked')], self::TODAY);
        $this->assertSame(['missing'], self::states($m, '1:30'));
        $this->assertSame(0, $m['cells']['1:30']['ok']);
    }

    public function testPendingAndExpiredNotHeldButRevokePendingIs(): void
    {
        foreach (['pending', 'expired'] as $status) {
            $m = MatrixBuilder::build(self::positions(1), self::roles(), [], [self::assignment(1)], [self::grant(90, $status)], self::TODAY);
            $this->assertArrayNotHasKey('1:30', $m['holders'], $status);
        }
        foreach (['revoke_pending', 'modify_pending'] as $status) {
            $m = MatrixBuilder::build(self::positions(1), self::roles(), [], [self::assignment(1)], [self::grant(90, $status)], self::TODAY);
            $this->assertSame(['unexpected'], self::states($m, '1:30'), $status);
        }
    }

    public function testUnknownRoleOrPositionIgnored(): void
    {
        $m = MatrixBuilder::build(
            self::positions(1),
            self::roles(),
            [self::cell(1, 'allowed', 999), self::cell(8, 'allowed')],
            [self::assignment(1)],
            [self::grant(90, 'active', self::USER, 999)],
            self::TODAY
        );
        $this->assertSame([], $m['cells']);
        $this->assertSame([], $m['holders']);
    }

    public function testPerformance200x300(): void
    {
        $positions = [];
        for ($p = 1; $p <= 200; $p++) {
            $positions[] = ['id' => $p, 'name' => "P$p", 'area' => 'A' . ($p % 10)];
        }
        $roles = [];
        for ($r = 1; $r <= 300; $r++) {
            $roles[] = ['id' => $r, 'name' => "R$r", 'level' => 'standard', 'plugin_iam_resources_id' => intdiv($r - 1, 5) + 1, 'resource_name' => 'Res' . (intdiv($r - 1, 5) + 1)];
        }
        $exps = ['allowed', 'allowed', 'on_request', 'forbidden'];
        $cells = [];
        for ($i = 0; $i < 6000; $i++) {
            $cells[] = ['plugin_iam_positions_id' => intdiv($i, 30) + 1, 'plugin_iam_roles_id' => ($i * 7) % 300 + 1, 'expectation' => $exps[$i % 4]];
        }
        $assignments = [];
        for ($u = 1; $u <= 2000; $u++) {
            $assignments[] = ['plugin_iam_positions_id' => $u % 200 + 1, 'users_id' => $u, 'date_begin' => null, 'date_end' => null];
            if ($u % 5 === 0) {
                $assignments[] = ['plugin_iam_positions_id' => ($u * 3) % 200 + 1, 'users_id' => $u, 'date_begin' => null, 'date_end' => $u % 2 ? '2026-01-01' : null];
            }
        }
        $grants = [];
        for ($g = 1; $g <= 10000; $g++) {
            $grants[] = ['id' => $g, 'users_id' => $g % 2000 + 1, 'plugin_iam_roles_id' => ($g * 13) % 300 + 1, 'status' => $g % 10 === 0 ? 'revoked' : 'active'];
        }

        $start = microtime(true);
        $m = MatrixBuilder::build($positions, $roles, $cells, $assignments, $grants, self::TODAY);
        $elapsed = microtime(true) - $start;

        $this->assertCount(200, $m['rows']);
        $this->assertCount(60, $m['cols']);
        $this->assertNotEmpty($m['cells']);
        $this->assertLessThan(1.0, $elapsed, sprintf('build took %.3f s', $elapsed));
    }
}
