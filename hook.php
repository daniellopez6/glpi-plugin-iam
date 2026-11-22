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
use GlpiPlugin\Iam\Scope;

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
 * Search restriction hook (search engine and API lists of every plugin itemtype): the SQL form of each class's
 * canViewItem(), centralised in Scope::criteriaFor() (see the predicate per itemtype there).
 *
 * @param string $itemtype
 * @return array<mixed>
 */
function plugin_iam_addDefaultWhere($itemtype): array
{
    return Scope::criteriaFor((string) $itemtype);
}
