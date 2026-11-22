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
 * Group membership closure (pure logic), same rule as GLPI 12 Session::loadGroups(): every direct group, plus, when a
 * group has recursive_membership, its child groups (recursively, a child without recursive_membership stops the
 * descent below it). Callers pass rows already restricted to the active entities.
 */
final class GroupMembership
{
    /**
     * @param list<array{groups_id:int|string, recursive_membership?:int|string|null}> $direct the user's
     *        glpi_groups_users rows joined with their group
     * @param list<array{id:int|string, groups_id:int|string, recursive_membership?:int|string|null}> $groups the
     *        candidate child groups (id, parent groups_id, recursive_membership)
     *
     * @return list<int>
     */
    public static function expand(array $direct, array $groups): array
    {
        $children = [];
        foreach ($groups as $g) {
            $children[(int) $g['groups_id']][] = ['id' => (int) $g['id'], 'recursive' => (int) ($g['recursive_membership'] ?? 0) === 1];
        }
        $out = [];
        $stack = [];
        foreach ($direct as $d) {
            $id = (int) $d['groups_id'];
            if ($id <= 0) {
                continue;
            }
            $out[$id] = true;
            if ((int) ($d['recursive_membership'] ?? 0) === 1) {
                $stack[] = $id;
            }
        }
        $seen = [];
        while ($stack !== []) {
            $parent = array_pop($stack);
            if (isset($seen[$parent])) {
                continue; // corrupted tree with a cycle: never loop
            }
            $seen[$parent] = true;
            foreach ($children[$parent] ?? [] as $child) {
                $out[$child['id']] = true;
                if ($child['recursive']) {
                    $stack[] = $child['id'];
                }
            }
        }
        return array_map('intval', array_keys($out));
    }
}
