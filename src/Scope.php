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

use Glpi\DBAL\QuerySubQuery;
use GlpiPlugin\Iam\Install\Schema;

/**
 * Single entry point of list visibility (search, API lists, the addDefaultWhere hook).
 *
 * Every predicate here is the SQL form of the class's canViewItem(); the classes own them (visibilityCriteria()):
 * - Position:      none added. GLPI's own entity restriction on the positions table is recursion-aware
 *                  (is_recursive column) and is exactly Position::canViewItem() (CommonDBTM: checkEntity(true)).
 * - Resource:      GLPI's recursive entity restriction, plus ownership (user or current group) without CONFIG READ.
 * - Role:          the role's resource is visible (Resource::visibilityCriteria(), recursion-aware). GLPI's entity
 *                  filter is disabled (isEntityAssign() = false): the roles table has no is_recursive column, so it
 *                  would hide the roles of a recursive resource of a parent entity from the child entities.
 * - Position_Role: position visible (recursion-aware) and the role's resource visible; GLPI's filter disabled for
 *                  the same reason (a cell takes the entity of the resource and has no is_recursive column).
 * - Grant:         the grant's resource is visible (ACCESS READ, or READ_OWNED and owned); GLPI's filter disabled.
 * - Note:          the target is visible, per target type; GLPI's filter disabled.
 * - Position_User: position and person visible (recursion-aware), on top of GLPI's filter of its own entity.
 */
final class Scope
{
    /** Tables with a class in this release => class covered by criteriaFor(). */
    public const COVERED = [
        Schema::PREFIX . 'positions'       => Position::class,
        Schema::PREFIX . 'positions_users' => Position_User::class,
        Schema::PREFIX . 'resources'       => Resource::class,
        Schema::PREFIX . 'roles'           => Role::class,
        Schema::PREFIX . 'positions_roles' => Position_Role::class,
        Schema::PREFIX . 'grants'          => Grant::class,
        Schema::PREFIX . 'notes'           => Note::class,
    ];

    /** Tables created by the installer whose classes come in later tasks: they must be covered when the class lands. */
    public const DEFERRED_TABLES = [
        Schema::PREFIX . 'grantusages',
        Schema::PREFIX . 'sodrules',
        Schema::PREFIX . 'deviations',
        Schema::PREFIX . 'campaigns',
        Schema::PREFIX . 'campaignitems',
        Schema::PREFIX . 'snapshots',
        Schema::PREFIX . 'reportlogs',
        Schema::PREFIX . 'entityconfigs',
    ];

    /** @return list<string> */
    public static function coveredItemtypes(): array
    {
        return array_values(self::COVERED);
    }

    /** Ids of the resources the session may see (Resource::canViewItem() in SQL). */
    public static function visibleResourcesSubQuery(): QuerySubQuery
    {
        $rt = Resource::getTable();
        return new QuerySubQuery(['SELECT' => "$rt.id", 'FROM' => $rt, 'WHERE' => [Resource::visibilityCriteria()]]);
    }

    /**
     * Criteria added to every list of a plugin itemtype (addDefaultWhere hook).
     *
     * @return array<mixed>
     */
    public static function criteriaFor(string $itemtype): array
    {
        return match ($itemtype) {
            Position::class      => [],
            Resource::class      => Resource::ownedOnly() ? [Resource::visibilityCriteria()] : [],
            Role::class          => [Role::visibilityCriteria()],
            Position_Role::class => [Position_Role::visibilityCriteria()],
            Grant::class         => [Grant::visibilityCriteria()],
            Note::class          => [Note::visibilityCriteria()],
            Position_User::class => [Position_User::visibilityCriteria()],
            default              => [],
        };
    }
}
