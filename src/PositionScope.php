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
 * Entity rules of the position tree (pure logic).
 */
final class PositionScope
{
    /**
     * A parent is acceptable when it lives in the child's entity, or when it is recursive and its entity is an
     * ancestor of the child's entity.
     *
     * @param list<int|string> $childAncestors ids of the ancestor entities of the child's entity
     */
    public static function parentAllowed(int $parentEntity, bool $parentRecursive, int $childEntity, array $childAncestors): bool
    {
        if ($parentEntity === $childEntity) {
            return true;
        }
        return $parentRecursive && in_array($parentEntity, array_map('intval', $childAncestors), true);
    }
}
