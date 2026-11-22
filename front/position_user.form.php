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
use GlpiPlugin\Iam\Position_User;

// Assignments are history: only add and update (set the end date); never delete or purge
$item = new Position_User();
if (isset($_POST['add'])) {
    $item->check(-1, CREATE, $_POST);
    $item->add($_POST);
} elseif (isset($_POST['update'])) {
    $item->check((int) $_POST['id'], UPDATE);
    $item->update($_POST);
} elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
    throw new \Glpi\Exception\Http\AccessDeniedHttpException();
} else {
    // Read-only page of an assignment, with its "Log (IAM)" tab
    $id = (int) ($_GET['id'] ?? 0);
    if ($id <= 0) {
        throw new \Glpi\Exception\Http\AccessDeniedHttpException();
    }
    $item->check($id, READ);
    Html::header(Position_User::getTypeName(1), $_SERVER['PHP_SELF'], plugin_iam_sector(), Menu::class, Position::class);
    $item->display(['id' => $id]);
    Html::footer();
    return;
}
Html::back();
