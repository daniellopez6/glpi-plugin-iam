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

$item = new Position();
if (isset($_POST['add'])) {
    $item->check(-1, CREATE, $_POST);
    $item->add($_POST);
} elseif (isset($_POST['update'])) {
    $item->check((int) $_POST['id'], UPDATE);
    $item->update($_POST);
} elseif (isset($_POST['purge']) || isset($_POST['delete'])) {
    // Positions have no trashbin; a position with assignments is refused by Position itself
    $item->check((int) $_POST['id'], PURGE);
    $item->delete($_POST, true);
    Html::redirect(Position::getSearchURL());
} else {
    $item->check((int) ($_GET['id'] ?? 0), READ);
    Html::header(Position::getTypeName(1), $_SERVER['PHP_SELF'], plugin_iam_sector(), Menu::class, Position::class);
    $item->display(['id' => (int) ($_GET['id'] ?? 0)]);
    Html::footer();
    return;
}
Html::back();
