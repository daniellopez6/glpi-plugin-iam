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

use GlpiPlugin\Iam\Grant;
use GlpiPlugin\Iam\Menu;

// The list is restricted by plugin_iam_addDefaultWhere (same predicate as Grant::canViewItem)
if (!Grant::canView()) {
    throw new \Glpi\Exception\Http\AccessDeniedHttpException();
}
Html::header(Grant::getTypeName(2), $_SERVER['PHP_SELF'], plugin_iam_sector(), Menu::class, Grant::class);
Search::show(Grant::class);
Html::footer();
