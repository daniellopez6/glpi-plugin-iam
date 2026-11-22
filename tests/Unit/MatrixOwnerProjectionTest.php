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

use GlpiPlugin\Iam\Matrix;
use GlpiPlugin\Iam\MatrixBuilder;
use GlpiPlugin\Iam\MatrixSummary;
use PHPUnit\Framework\TestCase;

/**
 * Sessions that see the register only through ownership (asset owners) must not receive who lacks an access, nor any
 * figure derived from it (expected, complete, missing): the projection strips them server side.
 */
final class MatrixOwnerProjectionTest extends TestCase
{
    private const TODAY = '2026-11-22';

    /** @return list<array<string,mixed>> */
    private static function roles(): array
    {
        return [
            ['id' => 30, 'name' => 'reader', 'level' => 'standard', 'plugin_iam_resources_id' => 5, 'resource_name' => 'ERP'],
            ['id' => 40, 'name' => 'user', 'level' => 'standard', 'plugin_iam_resources_id' => 6, 'resource_name' => 'VPN'],
        ];
    }

    /**
     * Row 1 allows ERP reader: 7 holds it, 8 lacks it; 7 also holds VPN unexpectedly. Row 2 is empty (no cell, nobody).
     *
     * @return array{model: array<string,mixed>, without: array<string,mixed>}
     */
    private static function fixture(): array
    {
        $positions = [['id' => 1, 'name' => 'Teller', 'area' => 'Ops > Cash'], ['id' => 2, 'name' => 'Clerk', 'area' => 'Back']];
        $cells = [['plugin_iam_positions_id' => 1, 'plugin_iam_roles_id' => 30, 'expectation' => 'allowed']];
        $assignments = [
            ['plugin_iam_positions_id' => 1, 'users_id' => 7, 'date_begin' => null, 'date_end' => null],
            ['plugin_iam_positions_id' => 1, 'users_id' => 8, 'date_begin' => null, 'date_end' => null],
        ];
        $grants = [
            ['id' => 90, 'users_id' => 7, 'plugin_iam_roles_id' => 30, 'status' => 'active'],
            ['id' => 91, 'users_id' => 7, 'plugin_iam_roles_id' => 40, 'status' => 'active'],
        ];
        return [
            'model'   => MatrixBuilder::build($positions, self::roles(), $cells, $assignments, $grants, self::TODAY),
            'without' => MatrixBuilder::withoutPosition(self::roles(), $assignments, $grants, self::TODAY),
        ];
    }

    public function testOwnerSummaryHasNoMissingNorExpectedFigures(): void
    {
        $f = self::fixture();
        $full = MatrixSummary::summarize($f['model'], $f['without']);
        $this->assertSame(1, $full['blocks']['1:5']['missing']);

        $owner = MatrixSummary::forOwner($full);
        $this->assertSame(
            ['expectation' => 'allowed', 'mixed' => false, 'holders' => 1, 'deviations' => 0, 'forbidden' => 0],
            $owner['blocks']['1:5']
        );
        foreach ($owner['blocks'] as $block) {
            $this->assertArrayNotHasKey('expected', $block);
            $this->assertArrayNotHasKey('complete', $block);
            $this->assertArrayNotHasKey('missing', $block);
        }
        $this->assertSame(['deviations' => 1], $owner['rows'][1]);
        $this->assertSame(['deviations' => 0], $owner['resources'][5]);
        $this->assertSame(['deviation_people' => 1, 'deviation_grants' => 1, 'forbidden_grants' => 0], $owner['totals']);
    }

    public function testOwnerClientCellsCarryOnlyHolderCounts(): void
    {
        $f = self::fixture();
        $this->assertSame(['a', 1, 2, 0, 0], MatrixSummary::clientCells($f['model'], $f['without'])['1:30']);
        $owner = MatrixSummary::clientCells($f['model'], $f['without'], false);
        $this->assertSame(['a', 1, null, 0, 0], $owner['1:30']);
        $this->assertSame(['', 0, null, 1, 0], $owner['1:40']);
    }

    public function testOwnerHoldersDropMissingPeople(): void
    {
        $f = self::fixture();
        $holders = $f['model']['holders']['1:30'];
        $this->assertSame(['ok', 'missing'], array_column($holders, 'state'));
        $this->assertSame($holders, MatrixSummary::visibleHolders($holders, true));
        $this->assertSame(
            [['users_id' => 7, 'state' => 'ok', 'grants_id' => 90]],
            MatrixSummary::visibleHolders($holders, false)
        );
    }

    public function testOwnerRowsWithoutBlocksAreHiddenWithTheirAreas(): void
    {
        $f = self::fixture();
        $summary = MatrixSummary::summarize($f['model'], $f['without']);
        $areas = [['id' => 100, 'name' => 'Back'], ['id' => 101, 'name' => 'Ops'], ['id' => 102, 'name' => 'Ops > Cash'], ['id' => 103, 'name' => 'Opsx']];
        $kept = MatrixSummary::onlyRowsWithBlocks($f['model'], $summary, $areas);
        $this->assertSame([1], array_column($kept['model']['rows'], 'id'));
        $this->assertSame([101, 102], array_column($kept['areas'], 'id'));
        $this->assertSame($f['model']['cols'], $kept['model']['cols']);
    }

    public function testOnlyTheMessagesQueuedSinceTheSnapshotAreTaken(): void
    {
        $before = [0 => ['Saved earlier'], 1 => ['Old &lt;b&gt;error']];
        $after = [0 => ['Saved earlier'], 1 => ['Old &lt;b&gt;error', 'Refused: <b>row</b> &amp; more'], 2 => ['Warn']];
        $this->assertSame(['Refused: row & more', 'Warn'], Matrix::messagesSince($before, $after));
        $this->assertSame(['A'], Matrix::messagesSince([], [1 => ['A']]));
    }
}
