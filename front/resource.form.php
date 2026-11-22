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
use GlpiPlugin\Iam\Resource;

$item = new Resource();
if (isset($_POST['add'])) {
    $item->check(-1, CREATE, $_POST);
    $item->add($_POST);
} elseif (isset($_POST['update'])) {
    $item->check((int) $_POST['id'], UPDATE);
    $item->update($_POST);
} elseif (isset($_POST['delete'])) {
    $item->check((int) $_POST['id'], DELETE);
    $item->delete($_POST);
    Html::redirect(Resource::getSearchURL());
} elseif (isset($_POST['restore'])) {
    $item->check((int) $_POST['id'], DELETE);
    $item->restore($_POST);
    Html::redirect(Resource::getSearchURL());
} elseif (isset($_POST['purge'])) {
    // A resource with grants or matrix cells is refused by Resource itself
    $item->check((int) $_POST['id'], PURGE);
    if ($item->delete($_POST, true)) {
        Html::redirect(Resource::getSearchURL());
    }
} else {
    $id = (int) ($_GET['id'] ?? 0);
    $item->check($id, READ);
    Html::header(Resource::getTypeName(1), $_SERVER['PHP_SELF'], plugin_iam_sector(), Menu::class, Resource::class);
    $item->display(['id' => $id, 'itemtype' => $_GET['itemtype'] ?? '', 'items_id' => $_GET['items_id'] ?? 0]);
    Html::footer();
    return;
}
Html::back();
