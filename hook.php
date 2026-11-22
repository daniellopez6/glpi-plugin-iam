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
use GlpiPlugin\Iam\Rights;

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
    if ($itemtype === Resource::class && Rights::onlyOwn() && !Session::haveRight(Rights::CONFIG, READ)) {
        return [Ownership::resourceCriteria(
            (int) Session::getLoginUserID(),
            array_values(array_map('intval', (array) ($_SESSION['glpigroups'] ?? []))),
            Resource::getTable()
        )];
    }
    return [];
}
