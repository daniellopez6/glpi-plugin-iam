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

use GlpiPlugin\Iam\Menu;
use GlpiPlugin\Iam\Position;

if (!Position::canView()) {
    throw new \Glpi\Exception\Http\AccessDeniedHttpException();
}
Html::header(Position::getTypeName(2), $_SERVER['PHP_SELF'], plugin_iam_sector(), Menu::class, Position::class);
Search::show(Position::class);
Html::footer();
