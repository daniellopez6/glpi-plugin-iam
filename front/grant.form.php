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

// The register keeps everything: add and update only (a revocation is a status change); no delete, restore or purge
$item = new Grant();
if (isset($_POST['add'])) {
    $item->check(-1, CREATE, $_POST);
    $id = $item->add($_POST);
    if ($id) {
        Html::redirect(Grant::getFormURLWithID((int) $id));
    }
} elseif (isset($_POST['update'])) {
    $item->check((int) $_POST['id'], UPDATE);
    $item->update($_POST);
} elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
    throw new \Glpi\Exception\Http\AccessDeniedHttpException();
} else {
    $id = (int) ($_GET['id'] ?? 0);
    if ($id > 0) {
        $item->check($id, READ);
    } elseif (!Grant::canCreate()) {
        throw new \Glpi\Exception\Http\AccessDeniedHttpException();
    }
    Html::header(Grant::getTypeName(1), $_SERVER['PHP_SELF'], plugin_iam_sector(), Menu::class, Grant::class);
    $item->display([
        'id'                      => $id,
        'plugin_iam_resources_id' => (int) ($_GET['plugin_iam_resources_id'] ?? 0),
        'users_id'                => (int) ($_GET['users_id'] ?? 0),
        'tickets_id'              => (int) ($_GET['tickets_id'] ?? 0),
    ]);
    Html::footer();
    return;
}
Html::back();
