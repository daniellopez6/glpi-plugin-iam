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

/**
 * Installation and uninstallation of the IAM plugin.
 */

use GlpiPlugin\Iam\Install\Installer;
use GlpiPlugin\Iam\Ownership;
use GlpiPlugin\Iam\Resource;
use GlpiPlugin\Iam\Position;
use GlpiPlugin\Iam\Position_Role;
use GlpiPlugin\Iam\Role;
use Glpi\DBAL\QuerySubQuery;

function plugin_iam_install(): bool
{
    Installer::install(new Migration(PLUGIN_IAM_VERSION));
    return true;
}

function plugin_iam_uninstall(): bool
{
    Installer::uninstall();
    return true;
}

/**
 * Search restriction hook. A profile that sees the register only through ownership ("See own") and has no read right
 * on the catalogue lists just the resources it owns (user or current group). The other itemtypes get their own
 * criteria in later releases.
 *
 * @param string $itemtype
 * @return array<mixed>
 */
function plugin_iam_addDefaultWhere($itemtype): array
{
    $where = [];
    // Cells: the position must be visible to the session (recursion-aware), for every session
    if ($itemtype === Position_Role::class) {
        $pt = Position::getTable();
        $where[] = [Position_Role::getTable() . '.plugin_iam_positions_id' => new QuerySubQuery([
            'SELECT' => "$pt.id",
            'FROM'   => $pt,
            'WHERE'  => getEntitiesRestrictCriteria($pt, '', '', true),
        ])];
    }
    // Same condition as Resource::canViewItem(): without CONFIG READ only owned resources (and their roles) are visible
    if (($itemtype === Resource::class || $itemtype === Role::class || $itemtype === Position_Role::class) && Resource::ownedOnly()) {
        $groups = array_values(array_map('intval', (array) ($_SESSION['glpigroups'] ?? [])));
        $own = Ownership::resourceCriteria((int) Session::getLoginUserID(), $groups, Resource::getTable());
        if ($itemtype === Resource::class) {
            return [$own];
        }
        $owned = new QuerySubQuery([
            'SELECT' => Resource::getTable() . '.id',
            'FROM'   => Resource::getTable(),
            'WHERE'  => [$own],
        ]);
        if ($itemtype === Position_Role::class) {
            // Cells of the roles of owned resources
            $where[] = [Position_Role::getTable() . '.plugin_iam_roles_id' => new QuerySubQuery([
                'SELECT' => Role::getTable() . '.id',
                'FROM'   => Role::getTable(),
                'WHERE'  => [Role::getTable() . '.plugin_iam_resources_id' => $owned],
            ])];
            return $where;
        }
        return [[Role::getTable() . '.plugin_iam_resources_id' => $owned]];
    }
    return $where;
}
