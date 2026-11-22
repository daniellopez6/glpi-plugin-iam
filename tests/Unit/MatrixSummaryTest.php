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
use GlpiPlugin\Iam\MatrixSummary;
use PHPUnit\Framework\TestCase;

final class MatrixSummaryTest extends TestCase
{
    private const TODAY = '2026-11-22';

    /** @return list<array<string,mixed>> */
    private static function roles(): array
    {
        return [
            ['id' => 30, 'name' => 'reader', 'level' => 'standard', 'plugin_iam_resources_id' => 5, 'resource_name' => 'ERP'],
            ['id' => 31, 'name' => 'admin', 'level' => 'privileged', 'plugin_iam_resources_id' => 5, 'resource_name' => 'ERP'],
            ['id' => 40, 'name' => 'user', 'level' => 'standard', 'plugin_iam_resources_id' => 6, 'resource_name' => 'VPN'],
        ];
    }

    /** @return array<string,mixed> */
    private static function cell(int $pos, int $role, string $expectation): array
    {
        return ['plugin_iam_positions_id' => $pos, 'plugin_iam_roles_id' => $role, 'expectation' => $expectation];
    }

    /** @return array<string,mixed> */
    private static function assignment(int $pos, int $user): array
    {
        return ['plugin_iam_positions_id' => $pos, 'users_id' => $user, 'date_begin' => null, 'date_end' => null];
    }

    /** @return array<string,mixed> */
    private static function grant(int $id, int $user, int $role): array
    {
        return ['id' => $id, 'users_id' => $user, 'plugin_iam_roles_id' => $role, 'status' => 'active'];
    }

    /**
     * Two positions; user 7 is in both and holds an unexpected VPN grant (counted once); user 8 lacks ERP reader;
     * user 9 has no position and holds ERP admin.
     *
     * @return array<string,mixed>
     */
    private static function summary(): array
    {
        $positions = [['id' => 1, 'name' => 'Teller', 'area' => 'Ops'], ['id' => 2, 'name' => 'Clerk', 'area' => 'Ops']];
        $cells = [self::cell(1, 30, 'allowed'), self::cell(1, 31, 'on_request'), self::cell(2, 30, 'forbidden')];
        $assignments = [self::assignment(1, 7), self::assignment(2, 7), self::assignment(1, 8)];
        $grants = [self::grant(90, 7, 30), self::grant(91, 7, 40), self::grant(92, 9, 31)];
        $model = MatrixBuilder::build($positions, self::roles(), $cells, $assignments, $grants, self::TODAY);
        $without = MatrixBuilder::withoutPosition(self::roles(), $assignments, $grants, self::TODAY);
        return MatrixSummary::summarize($model, $without);
    }

    public function testBlockAggregatesDistinctPeoplePerResource(): void
    {
        $s = self::summary();
        // Row 1 / ERP: reader allowed (7 ok, 8 missing), admin on request: most permissive glyph, mixed
        $this->assertSame(
            ['expectation' => 'allowed', 'mixed' => true, 'expected' => 2, 'complete' => 1, 'holders' => 1, 'missing' => 1, 'deviations' => 0, 'forbidden' => 0],
            $s['blocks']['1:5']
        );
        // Row 2 / ERP: forbidden, but 7 is allowed by row 1, so no deviation
        $this->assertSame('forbidden', $s['blocks']['2:5']['expectation']);
        $this->assertSame(0, $s['blocks']['2:5']['deviations']);
        // VPN: unexpected for 7 in both rows
        $this->assertSame(1, $s['blocks']['1:6']['deviations']);
        $this->assertSame(1, $s['blocks']['2:6']['deviations']);
        $this->assertNull($s['blocks']['1:6']['expectation']);
    }

    public function testNoPositionBucketIsRowZero(): void
    {
        $s = self::summary();
        $this->assertSame(1, $s['blocks']['0:5']['deviations']);
        $this->assertSame(['deviations' => 1, 'missing' => 0], $s['rows'][0]);
    }

    public function testTotalsCountDistinctPeopleAndGrants(): void
    {
        $s = self::summary();
        // People with deviations: 7 (VPN, two rows -> once) and 9 (no position)
        $this->assertSame(['deviation_people' => 2, 'deviation_grants' => 2, 'missing_people' => 1, 'forbidden_grants' => 0], $s['totals']);
        $this->assertSame(['deviations' => 1, 'missing' => 1], $s['resources'][5]);
        $this->assertSame(['deviations' => 1, 'missing' => 0], $s['resources'][6]);
        $this->assertSame(['deviations' => 1, 'missing' => 1], $s['rows'][1]);
        $this->assertSame(['deviations' => 1, 'missing' => 0], $s['rows'][2]);
    }

    public function testForbiddenHeldIsCountedApart(): void
    {
        $model = MatrixBuilder::build(
            [['id' => 1, 'name' => 'Teller', 'area' => '']],
            self::roles(),
            [self::cell(1, 31, 'forbidden')],
            [self::assignment(1, 7)],
            [self::grant(90, 7, 31)],
            self::TODAY
        );
        $s = MatrixSummary::summarize($model, ['cells' => [], 'holders' => []]);
        $this->assertSame(1, $s['blocks']['1:5']['forbidden']);
        $this->assertSame(1, $s['blocks']['1:5']['deviations']);
        $this->assertSame(1, $s['totals']['forbidden_grants']);
    }

    public function testOnlyDeviationsKeepsRowsAndColumnsWithDeviations(): void
    {
        $positions = [['id' => 1, 'name' => 'Teller', 'area' => 'Ops'], ['id' => 2, 'name' => 'Clerk', 'area' => 'Ops']];
        $model = MatrixBuilder::build(
            $positions,
            self::roles(),
            [self::cell(1, 30, 'allowed'), self::cell(2, 30, 'allowed')],
            [self::assignment(1, 7), self::assignment(2, 8)],
            [self::grant(90, 7, 30), self::grant(91, 8, 30), self::grant(92, 8, 40)],
            self::TODAY
        );
        $s = MatrixSummary::summarize($model, ['cells' => [], 'holders' => []]);
        $kept = MatrixSummary::onlyDeviations($model, $s);
        $this->assertSame([2], array_column($kept['rows'], 'id'));
        $this->assertSame([6], array_column($kept['cols'], 'resource_id'));
    }

    public function testRowsFromPositionTree(): void
    {
        $positions = [
            ['id' => 10, 'name' => 'IT', 'completename' => 'IT', 'plugin_iam_positions_id' => 0, 'is_active' => 1],
            ['id' => 11, 'name' => 'Developer', 'completename' => 'IT > Developer', 'plugin_iam_positions_id' => 10, 'is_active' => 1],
            ['id' => 12, 'name' => 'Admin', 'completename' => 'IT > Admin', 'plugin_iam_positions_id' => 10, 'is_active' => 1],
            ['id' => 13, 'name' => 'Old', 'completename' => 'IT > Old', 'plugin_iam_positions_id' => 10, 'is_active' => 0],
            ['id' => 20, 'name' => 'Board', 'completename' => 'Board', 'plugin_iam_positions_id' => 0, 'is_active' => 1],
            ['id' => 21, 'name' => 'CEO', 'completename' => 'Board > CEO', 'plugin_iam_positions_id' => 20, 'is_active' => 1],
            ['id' => 30, 'name' => 'Auditor', 'completename' => 'Auditor', 'plugin_iam_positions_id' => 0, 'is_active' => 1],
        ];
        // Board (an area) has its own expectations: it is also a row
        $r = MatrixSummary::rows($positions, [20 => true]);
        $this->assertSame(
            [
                ['id' => 30, 'name' => 'Auditor', 'area' => ''],
                ['id' => 20, 'name' => 'Board', 'area' => ''],
                ['id' => 21, 'name' => 'CEO', 'area' => 'Board'],
                ['id' => 12, 'name' => 'Admin', 'area' => 'IT'],
                ['id' => 11, 'name' => 'Developer', 'area' => 'IT'],
            ],
            $r['rows']
        );
        $this->assertSame([['id' => 20, 'name' => 'Board'], ['id' => 10, 'name' => 'IT']], $r['areas']);

        $it = MatrixSummary::rows($positions, [20 => true], 10);
        $this->assertSame([12, 11], array_column($it['rows'], 'id'));
        $this->assertCount(2, $it['areas']);
    }

    public function testAreaFilterIncludesDeepDescendants(): void
    {
        $positions = [
            ['id' => 1, 'name' => 'Ops', 'completename' => 'Ops', 'plugin_iam_positions_id' => 0, 'is_active' => 1],
            ['id' => 2, 'name' => 'Cash', 'completename' => 'Ops > Cash', 'plugin_iam_positions_id' => 1, 'is_active' => 1],
            ['id' => 3, 'name' => 'Teller', 'completename' => 'Ops > Cash > Teller', 'plugin_iam_positions_id' => 2, 'is_active' => 1],
            ['id' => 4, 'name' => 'Other', 'completename' => 'Other', 'plugin_iam_positions_id' => 0, 'is_active' => 1],
        ];
        $r = MatrixSummary::rows($positions, [], 1);
        $this->assertSame([['id' => 3, 'name' => 'Teller', 'area' => 'Ops > Cash']], $r['rows']);
    }

    public function testClientCellsAreCompact(): void
    {
        $model = MatrixBuilder::build(
            [['id' => 1, 'name' => 'Teller', 'area' => '']],
            self::roles(),
            [self::cell(1, 30, 'allowed'), self::cell(1, 31, 'on_request'), self::cell(1, 40, 'forbidden')],
            [self::assignment(1, 7)],
            [self::grant(90, 7, 30)],
            self::TODAY
        );
        $without = ['cells' => ['0:40' => ['expectation' => null, 'ok' => 0, 'expected' => 0, 'unexpected' => 2, 'forbidden_held' => 0]], 'holders' => []];
        $this->assertSame(
            ['1:30' => ['a', 1, 1, 0, 0], '1:31' => ['r', 0, 0, 0, 0], '1:40' => ['f', 0, 0, 0, 0], '0:40' => ['', 0, 0, 2, 0]],
            MatrixSummary::clientCells($model, $without)
        );
    }
}
