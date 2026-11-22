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

function plugin_iam_install(): bool
{
    return true;
}

function plugin_iam_uninstall(): bool
{
    return true;
}

/**
 * Search restriction hook; the access-governance itemtypes add their own criteria in later releases.
 *
 * @param string $itemtype
 * @return array<mixed>
 */
function plugin_iam_addDefaultWhere($itemtype): array
{
    return [];
}
