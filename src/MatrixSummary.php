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
 * Presentation aggregates of the matrix model (pure logic, no I/O).
 *
 * The page shows one column per resource (collapsed) until the user expands it into its roles. Aggregates count
 * DISTINCT PEOPLE: a person with two positions, or several roles of the same resource, is counted once per block,
 * once per resource column and once in the totals.
 */
final class MatrixSummary
{
    /** Most permissive first: the glyph of a collapsed block is the most permissive expectation of its roles. */
    private const PERMISSIVENESS = ['allowed' => 3, 'on_request' => 2, 'forbidden' => 1];

    /** Compact expectation codes for the client (role-level cells). */
    private const CODES = ['allowed' => 'a', 'on_request' => 'r', 'forbidden' => 'f'];

    private const DEVIATION_STATES = ['unexpected' => true, 'forbidden_held' => true];

    /**
     * Rows of the matrix from the positions tree. A row is an active position that is a leaf, or that carries data
     * of its own ($withData: ids with an expectation or an assignment); the area is the full name of the parent ('' at
     * the top). Rows are sorted by area then name. Areas (positions with children) are listed for the filter.
     * With $areaId, only the descendants (any depth) of that area are rows.
     *
     * @param list<array<string,mixed>> $positions id, name, completename, plugin_iam_positions_id, is_active
     * @param array<int,true>           $withData
     *
     * @return array{rows: list<array{id:int, name:string, area:string}>, areas: list<array{id:int, name:string}>}
     */
    public static function rows(array $positions, array $withData, int $areaId = 0): array
    {
        $byId = [];
        $children = [];
        foreach ($positions as $p) {
            $id = (int) ($p['id'] ?? 0);
            if ($id <= 0) {
                continue;
            }
            $byId[$id] = $p;
            $children[(int) ($p['plugin_iam_positions_id'] ?? 0)][] = $id;
        }
        $inArea = null;
        if ($areaId > 0) {
            $inArea = [];
            $stack = $children[$areaId] ?? [];
            while ($stack !== []) {
                $id = array_pop($stack);
                if (isset($inArea[$id])) {
                    continue;
                }
                $inArea[$id] = true;
                foreach ($children[$id] ?? [] as $child) {
                    $stack[] = $child;
                }
            }
        }
        $rows = [];
        $areas = [];
        foreach ($byId as $id => $p) {
            if (isset($children[$id])) {
                $areas[] = ['id' => $id, 'name' => (string) ($p['completename'] ?? $p['name'] ?? '')];
            }
            if ((int) ($p['is_active'] ?? 1) !== 1 || (isset($children[$id]) && !isset($withData[$id]))) {
                continue;
            }
            if ($inArea !== null && !isset($inArea[$id])) {
                continue;
            }
            $parent = $byId[(int) ($p['plugin_iam_positions_id'] ?? 0)] ?? null;
            $rows[] = [
                'id'   => $id,
                'name' => (string) ($p['name'] ?? ''),
                'area' => $parent === null ? '' : (string) ($parent['completename'] ?? $parent['name'] ?? ''),
            ];
        }
        usort($rows, static fn (array $a, array $b): int => [$a['area'], $a['name'], $a['id']] <=> [$b['area'], $b['name'], $b['id']]);
        usort($areas, static fn (array $a, array $b): int => [$a['name'], $a['id']] <=> [$b['name'], $b['id']]);
        return ['rows' => $rows, 'areas' => $areas];
    }

    /**
     * Aggregates of a model (MatrixBuilder::build()) plus its "No active position" bucket (withoutPosition()).
     *
     * - blocks:    "posId:resourceId" => {expectation: most permissive expectation of the row on the resource's roles
     *              (null: none), mixed: the roles have different expectations, expected: people expected to hold an
     *              allowed role, complete: expected people missing nothing, holders: people holding a justified role,
     *              missing, deviations (unexpected or forbidden held), forbidden (forbidden held)} — distinct people
     * - rows:      posId => {deviations, missing} distinct people (posId 0 = the bucket)
     * - resources: resourceId => {deviations, missing} distinct people over every row and the bucket
     * - totals:    deviation_people, deviation_grants, missing_people (distinct), forbidden_grants
     *
     * @param array<string,mixed> $model
     * @param array<string,mixed> $without
     *
     * @return array{
     *     blocks: array<string, array{expectation:?string, mixed:bool, expected:int, complete:int, holders:int, missing:int, deviations:int, forbidden:int}>,
     *     rows: array<int, array{deviations:int, missing:int}>,
     *     resources: array<int, array{deviations:int, missing:int}>,
     *     totals: array{deviation_people:int, deviation_grants:int, missing_people:int, forbidden_grants:int}
     * }
     */
    public static function summarize(array $model, array $without): array
    {
        $resOf = [];
        $resources = [];
        foreach ((array) ($model['cols'] ?? []) as $col) {
            $resId = (int) $col['resource_id'];
            $resources[$resId] = ['deviations' => [], 'missing' => []];
            foreach ($col['roles'] as $role) {
                $resOf[(int) $role['id']] = $resId;
            }
        }
        $rows = [MatrixBuilder::NO_POSITION => ['deviations' => [], 'missing' => []]];
        foreach ((array) ($model['rows'] ?? []) as $row) {
            $rows[(int) $row['id']] = ['deviations' => [], 'missing' => []];
        }

        $cells = (array) ($model['cells'] ?? []) + (array) ($without['cells'] ?? []);
        $holders = (array) ($model['holders'] ?? []) + (array) ($without['holders'] ?? []);

        /** @var array<string, array{exp: array<string,true>, expected: array<int,true>, holders: array<int,true>, missing: array<int,true>, deviations: array<int,true>, forbidden: array<int,true>}> $acc */
        $acc = [];
        $blank = ['exp' => [], 'expected' => [], 'holders' => [], 'missing' => [], 'deviations' => [], 'forbidden' => []];
        foreach ($cells as $key => $cell) {
            [$pos, $roleId] = array_map('intval', explode(':', (string) $key));
            if (!isset($resOf[$roleId])) {
                continue;
            }
            $bk = $pos . ':' . $resOf[$roleId];
            $acc[$bk] ??= $blank;
            if (($cell['expectation'] ?? null) !== null) {
                $acc[$bk]['exp'][(string) $cell['expectation']] = true;
            }
        }
        $devPeople = [];
        $devGrants = [];
        $missPeople = [];
        $forbiddenGrants = [];
        foreach ($holders as $key => $list) {
            [$pos, $roleId] = array_map('intval', explode(':', (string) $key));
            if (!isset($resOf[$roleId])) {
                continue;
            }
            $resId = $resOf[$roleId];
            $bk = $pos . ':' . $resId;
            $acc[$bk] ??= $blank;
            $allowed = ($cells[$key]['expectation'] ?? null) === 'allowed';
            foreach ($list as $h) {
                $user = (int) $h['users_id'];
                $state = (string) $h['state'];
                if ($state === 'missing') {
                    $acc[$bk]['missing'][$user] = true;
                    $acc[$bk]['expected'][$user] = true;
                    $rows[$pos]['missing'][$user] = true;
                    $resources[$resId]['missing'][$user] = true;
                    $missPeople[$user] = true;
                } elseif ($state === 'ok') {
                    $acc[$bk]['holders'][$user] = true;
                    if ($allowed) {
                        $acc[$bk]['expected'][$user] = true;
                    }
                } elseif (isset(self::DEVIATION_STATES[$state])) {
                    $acc[$bk]['deviations'][$user] = true;
                    $rows[$pos]['deviations'][$user] = true;
                    $resources[$resId]['deviations'][$user] = true;
                    $devPeople[$user] = true;
                    $devGrants[(int) $h['grants_id']] = true;
                    if ($state === 'forbidden_held') {
                        $acc[$bk]['forbidden'][$user] = true;
                        $forbiddenGrants[(int) $h['grants_id']] = true;
                    }
                }
            }
        }

        $blocks = [];
        foreach ($acc as $bk => $a) {
            $exp = array_keys($a['exp']);
            usort($exp, static fn (string $x, string $y): int => (self::PERMISSIVENESS[$y] ?? 0) <=> (self::PERMISSIVENESS[$x] ?? 0));
            $blocks[$bk] = [
                'expectation' => $exp[0] ?? null,
                'mixed'       => count($exp) > 1,
                'expected'    => count($a['expected']),
                'complete'    => count($a['expected']) - count($a['missing']),
                'holders'     => count($a['holders']),
                'missing'     => count($a['missing']),
                'deviations'  => count($a['deviations']),
                'forbidden'   => count($a['forbidden']),
            ];
        }
        $count = static fn (array $sets): array => ['deviations' => count($sets['deviations']), 'missing' => count($sets['missing'])];
        return [
            'blocks'    => $blocks,
            'rows'      => array_map($count, $rows),
            'resources' => array_map($count, $resources),
            'totals'    => [
                'deviation_people' => count($devPeople),
                'deviation_grants' => count($devGrants),
                'missing_people'   => count($missPeople),
                'forbidden_grants' => count($forbiddenGrants),
            ],
        ];
    }

    /**
     * The model restricted to the rows and resource columns that have at least one deviation.
     *
     * @param array<string,mixed> $model
     * @param array<string,mixed> $summary
     * @return array<string,mixed>
     */
    public static function onlyDeviations(array $model, array $summary): array
    {
        $model['rows'] = array_values(array_filter(
            (array) $model['rows'],
            static fn (array $r): bool => ($summary['rows'][(int) $r['id']]['deviations'] ?? 0) > 0
        ));
        $model['cols'] = array_values(array_filter(
            (array) $model['cols'],
            static fn (array $c): bool => ($summary['resources'][(int) $c['resource_id']]['deviations'] ?? 0) > 0
        ));
        return $model;
    }

    /**
     * Role-level cells for the client: "posId:roleId" => [expectation code ('a' allowed, 'r' on request,
     * 'f' forbidden, '' none), ok, expected, unexpected, forbidden_held]. Missing = expected - ok on allowed cells.
     *
     * @param array<string,mixed> $model
     * @param array<string,mixed> $without
     * @return array<string, array{0:string, 1:int, 2:int, 3:int, 4:int}>
     */
    public static function clientCells(array $model, array $without): array
    {
        $out = [];
        foreach ((array) ($model['cells'] ?? []) + (array) ($without['cells'] ?? []) as $key => $c) {
            $out[(string) $key] = [
                self::CODES[(string) ($c['expectation'] ?? '')] ?? '',
                (int) $c['ok'],
                (int) $c['expected'],
                (int) $c['unexpected'],
                (int) $c['forbidden_held'],
            ];
        }
        return $out;
    }
}
