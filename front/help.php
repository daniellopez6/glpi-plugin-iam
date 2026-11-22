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

use GlpiPlugin\Iam\Help;
use GlpiPlugin\Iam\Menu;

if (!Help::canView()) {
    throw new \Glpi\Exception\Http\AccessDeniedHttpException();
}

Html::header(Help::getTypeName(), $_SERVER['PHP_SELF'], plugin_iam_sector(), Menu::class, 'help');
Help::show();
Html::footer();
