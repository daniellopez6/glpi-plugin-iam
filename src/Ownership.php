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
 * Ownership of resources (pure logic: callers pass the user id and group ids read at request time).
 */
final class Ownership
{
    /**
     * Criteria (DBmysqlIterator style) selecting the resources owned by the user or one of the groups.
     *
     * @param list<int|string> $groupIds
     *
     * @return array<string, mixed>
     */
    public static function resourceCriteria(int $uid, array $groupIds, string $resourcesTable): array
    {
        if ($uid <= 0) {
            return ["$resourcesTable.id" => 0];
        }

        $or = ["$resourcesTable.users_id_owner" => $uid];
        $groups = self::cleanGroups($groupIds);
        if ($groups !== []) {
            $or["$resourcesTable.groups_id_owner"] = $groups;
        }

        return ['OR' => $or];
    }

    /**
     * @param array<string, mixed> $resourceFields
     * @param list<int|string>     $groupIds
     */
    public static function isOwner(array $resourceFields, int $uid, array $groupIds): bool
    {
        if ($uid <= 0) {
            return false;
        }

        if ((int) ($resourceFields['users_id_owner'] ?? 0) === $uid) {
            return true;
        }

        $ownerGroup = (int) ($resourceFields['groups_id_owner'] ?? 0);

        return $ownerGroup > 0 && in_array($ownerGroup, self::cleanGroups($groupIds), true);
    }

    /**
     * @param list<int|string> $groupIds
     *
     * @return list<int>
     */
    private static function cleanGroups(array $groupIds): array
    {
        $ids = array_map('intval', $groupIds);

        return array_values(array_unique(array_filter($ids, static fn(int $id): bool => $id > 0)));
    }
}
