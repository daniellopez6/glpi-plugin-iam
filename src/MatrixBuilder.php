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

namespace GlpiPlugin\Iam;

/**
 * Model of the RBAC matrix (positions x roles) with the people behind each cell (pure logic, no I/O).
 *
 * Expected access of a person = union of the cells of their ACTIVE positions (spec §8, Review Focus 1): an assignment
 * counts when PositionPeriod::isActive(date_begin, date_end, today). A grant is held while it still exists in the real
 * system: status active, revoke_pending or modify_pending ('pending', 'revoked', 'expired' are not held).
 */
final class MatrixBuilder
{
    public const HELD_STATUSES = ['active', 'revoke_pending', 'modify_pending'];

    /** Row id of the "No active position" bucket (see withoutPosition()). */
    public const NO_POSITION = 0;

    /** Expectations that justify a held grant ('on_request' needs no grant, but justifies one when it exists). */
    private const JUSTIFYING = ['allowed' => true, 'on_request' => true];

    /**
     * Builds the matrix model.
     *
     * Input rows are plain arrays as read from the database (extra keys are ignored):
     * - $positions:   rows of the matrix, in display order: id, name, area (optional, e.g. a group name aliased by the caller)
     * - $roles:       columns, in display order (grouped by resource in order of first appearance): id, name, level,
     *                 plugin_iam_resources_id, resource_name
     * - $cells:       positions_roles rows: plugin_iam_positions_id, plugin_iam_roles_id, expectation
     * - $assignments: positions_users rows: plugin_iam_positions_id, users_id, date_begin, date_end ('Y-m-d' or null)
     * - $grants:      grants rows: id, users_id, plugin_iam_roles_id, status
     *
     * Cells and assignments of positions that are not rows (e.g. not visible to the viewer) still count to justify a
     * grant held by a person of a visible row; pass every active assignment of the people concerned and their cells.
     * Cells and grants on roles that are not columns are ignored.
     *
     * Output:
     * - rows:    list<{id, name, area}>
     * - cols:    list<{resource_id, resource, roles: list<{id, name, level}>}>
     * - cells:   "posId:roleId" => {expectation: ?string, ok, expected, unexpected, forbidden_held}; present only for a
     *            row with an expectation on the role, or with at least one holder (absent = no expectation, nobody)
     * - holders: "posId:roleId" => list<{users_id, state: 'ok'|'missing'|'unexpected'|'forbidden_held', grants_id: ?int}>
     *            sorted by users_id. A person of the row whose grant is justified by ANOTHER active position (the row
     *            has no expectation or forbids it) is not listed in that row: they appear as 'ok' in the justifying row.
     *
     * Per cell (P, R) and person u of row P (active assignment to P):
     * - ok:             u holds R and P's expectation is allowed or on_request
     * - missing:        u does not hold R and P's expectation is allowed (on_request is never missing)
     * - unexpected:     u holds R, P has no expectation, and no active position of u has any expectation on R
     * - forbidden_held: u holds R, P forbids it, and no other active position of u allows it (allowed / on_request)
     * - expected:       number of people of P when P's expectation is allowed
     *
     * @param list<array<string,mixed>> $positions
     * @param list<array<string,mixed>> $roles
     * @param list<array<string,mixed>> $cells
     * @param list<array<string,mixed>> $assignments
     * @param list<array<string,mixed>> $grants
     *
     * @return array{
     *     rows: list<array{id:int, name:string, area:string}>,
     *     cols: list<array{resource_id:int, resource:string, roles:list<array{id:int, name:string, level:string}>}>,
     *     cells: array<string, array{expectation:?string, ok:int, expected:int, unexpected:int, forbidden_held:int}>,
     *     holders: array<string, list<array{users_id:int, state:string, grants_id:?int}>>
     * }
     */
    public static function build(array $positions, array $roles, array $cells, array $assignments, array $grants, string $today): array
    {
        // Rows
        $rows = [];
        $isRow = [];
        foreach ($positions as $p) {
            $id = (int) ($p['id'] ?? 0);
            if ($id <= 0 || isset($isRow[$id])) {
                continue;
            }
            $isRow[$id] = true;
            $rows[] = ['id' => $id, 'name' => (string) ($p['name'] ?? ''), 'area' => (string) ($p['area'] ?? '')];
        }

        // Columns, grouped by resource
        $cols = [];
        $colIndex = [];
        $isRole = [];
        foreach ($roles as $r) {
            $id = (int) ($r['id'] ?? 0);
            if ($id <= 0 || isset($isRole[$id])) {
                continue;
            }
            $isRole[$id] = true;
            $resId = (int) ($r['plugin_iam_resources_id'] ?? 0);
            if (!isset($colIndex[$resId])) {
                $colIndex[$resId] = count($cols);
                $cols[] = ['resource_id' => $resId, 'resource' => (string) ($r['resource_name'] ?? ''), 'roles' => []];
            }
            $cols[$colIndex[$resId]]['roles'][] = ['id' => $id, 'name' => (string) ($r['name'] ?? ''), 'level' => (string) ($r['level'] ?? '')];
        }

        // Expectations: position => role => expectation (every position, rows or not)
        $exp = [];
        foreach ($cells as $c) {
            $roleId = (int) ($c['plugin_iam_roles_id'] ?? 0);
            if (!isset($isRole[$roleId])) {
                continue;
            }
            $exp[(int) ($c['plugin_iam_positions_id'] ?? 0)][$roleId] = (string) ($c['expectation'] ?? '');
        }

        // Active positions per person, and people per row
        $activeOf = [];
        $members = [];
        foreach ($assignments as $a) {
            $begin = isset($a['date_begin']) ? (string) $a['date_begin'] : null;
            $end = isset($a['date_end']) ? (string) $a['date_end'] : null;
            if (!PositionPeriod::isActive($begin, $end, $today)) {
                continue;
            }
            $user = (int) ($a['users_id'] ?? 0);
            $pos = (int) ($a['plugin_iam_positions_id'] ?? 0);
            if ($user <= 0 || $pos <= 0) {
                continue;
            }
            $activeOf[$user][$pos] = true;
            if (isset($isRow[$pos])) {
                $members[$pos][$user] = true;
            }
        }

        // Held grants: person => role => lowest grant id
        $held = [];
        $heldStatuses = array_flip(self::HELD_STATUSES);
        foreach ($grants as $g) {
            $roleId = (int) ($g['plugin_iam_roles_id'] ?? 0);
            if (!isset($isRole[$roleId]) || !isset($heldStatuses[(string) ($g['status'] ?? '')])) {
                continue;
            }
            $user = (int) ($g['users_id'] ?? 0);
            $gid = (int) ($g['id'] ?? 0);
            if (!isset($held[$user][$roleId]) || $gid < $held[$user][$roleId]) {
                $held[$user][$roleId] = $gid;
            }
        }

        $outCells = [];
        $outHolders = [];
        foreach ($rows as $row) {
            $pos = $row['id'];
            $rowExp = $exp[$pos] ?? [];
            foreach ($rowExp as $roleId => $e) {
                $outCells["$pos:$roleId"] = self::emptyCell($e);
            }
            $users = array_keys($members[$pos] ?? []);
            sort($users);
            foreach ($users as $user) {
                $userHeld = $held[$user] ?? [];
                // Roles with an expectation in this row
                foreach ($rowExp as $roleId => $e) {
                    $key = "$pos:$roleId";
                    $gid = $userHeld[$roleId] ?? null;
                    if ($e === 'allowed') {
                        $outCells[$key]['expected']++;
                    }
                    if ($gid === null) {
                        if ($e === 'allowed') {
                            $outHolders[$key][] = ['users_id' => $user, 'state' => 'missing', 'grants_id' => null];
                        }
                        continue;
                    }
                    if (isset(self::JUSTIFYING[$e])) {
                        $outCells[$key]['ok']++;
                        $outHolders[$key][] = ['users_id' => $user, 'state' => 'ok', 'grants_id' => $gid];
                    } elseif ($e === 'forbidden' && !self::justifiedElsewhere($exp, $activeOf[$user], $pos, $roleId)) {
                        $outCells[$key]['forbidden_held']++;
                        $outHolders[$key][] = ['users_id' => $user, 'state' => 'forbidden_held', 'grants_id' => $gid];
                    }
                }
                // Held roles without expectation in this row: unexpected only if no active position has any expectation
                foreach ($userHeld as $roleId => $gid) {
                    if (isset($rowExp[$roleId]) || self::hasAnyExpectation($exp, $activeOf[$user], $roleId)) {
                        continue;
                    }
                    $key = "$pos:$roleId";
                    $outCells[$key] ??= self::emptyCell(null);
                    $outCells[$key]['unexpected']++;
                    $outHolders[$key][] = ['users_id' => $user, 'state' => 'unexpected', 'grants_id' => $gid];
                }
            }
        }

        return ['rows' => $rows, 'cols' => $cols, 'cells' => $outCells, 'holders' => $outHolders];
    }

    /**
     * The "No active position" row: people who hold a grant on a column role but have no active assignment at all
     * (ended, future or none). Every such grant is unexpected: no position justifies it.
     *
     * Same input shapes as build(); the row id is NO_POSITION, so keys are "0:roleId". One holder entry per person and
     * role (lowest grant id), sorted by users_id.
     *
     * @param list<array<string,mixed>> $roles
     * @param list<array<string,mixed>> $assignments
     * @param list<array<string,mixed>> $grants
     *
     * @return array{
     *     cells: array<string, array{expectation:?string, ok:int, expected:int, unexpected:int, forbidden_held:int}>,
     *     holders: array<string, list<array{users_id:int, state:string, grants_id:?int}>>
     * }
     */
    public static function withoutPosition(array $roles, array $assignments, array $grants, string $today): array
    {
        $isRole = [];
        foreach ($roles as $r) {
            $isRole[(int) ($r['id'] ?? 0)] = true;
        }
        $placed = [];
        foreach ($assignments as $a) {
            $begin = isset($a['date_begin']) ? (string) $a['date_begin'] : null;
            $end = isset($a['date_end']) ? (string) $a['date_end'] : null;
            if ((int) ($a['plugin_iam_positions_id'] ?? 0) > 0 && PositionPeriod::isActive($begin, $end, $today)) {
                $placed[(int) ($a['users_id'] ?? 0)] = true;
            }
        }
        // role => person => lowest grant id
        $held = [];
        $heldStatuses = array_flip(self::HELD_STATUSES);
        foreach ($grants as $g) {
            $roleId = (int) ($g['plugin_iam_roles_id'] ?? 0);
            $user = (int) ($g['users_id'] ?? 0);
            if ($user <= 0 || isset($placed[$user]) || !isset($isRole[$roleId]) || !isset($heldStatuses[(string) ($g['status'] ?? '')])) {
                continue;
            }
            $gid = (int) ($g['id'] ?? 0);
            if (!isset($held[$roleId][$user]) || $gid < $held[$roleId][$user]) {
                $held[$roleId][$user] = $gid;
            }
        }
        $cells = [];
        $holders = [];
        foreach ($held as $roleId => $users) {
            ksort($users);
            $key = self::NO_POSITION . ':' . $roleId;
            $cells[$key] = self::emptyCell(null);
            $cells[$key]['unexpected'] = count($users);
            foreach ($users as $user => $gid) {
                $holders[$key][] = ['users_id' => $user, 'state' => 'unexpected', 'grants_id' => $gid];
            }
        }
        return ['cells' => $cells, 'holders' => $holders];
    }

    /** @return array{expectation:?string, ok:int, expected:int, unexpected:int, forbidden_held:int} */
    private static function emptyCell(?string $expectation): array
    {
        return ['expectation' => $expectation, 'ok' => 0, 'expected' => 0, 'unexpected' => 0, 'forbidden_held' => 0];
    }

    /**
     * @param array<int, array<int, string>> $exp
     * @param array<int, true>               $active
     */
    private static function justifiedElsewhere(array $exp, array $active, int $pos, int $roleId): bool
    {
        foreach ($active as $other => $_) {
            if ($other !== $pos && isset(self::JUSTIFYING[$exp[$other][$roleId] ?? ''])) {
                return true;
            }
        }
        return false;
    }

    /**
     * @param array<int, array<int, string>> $exp
     * @param array<int, true>               $active
     */
    private static function hasAnyExpectation(array $exp, array $active, int $roleId): bool
    {
        foreach ($active as $pos => $_) {
            if (isset($exp[$pos][$roleId])) {
                return true;
            }
        }
        return false;
    }
}
