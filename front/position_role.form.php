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

use GlpiPlugin\Iam\Position_Role;

// A cell is configuration: add, change the expectation, or remove it (back to "no expectation"). Rights are
// checked on the item (CONFIG); the matrix screen itself is a later task.
$item = new Position_Role();
if (isset($_POST['add'])) {
    $item->check(-1, CREATE, $_POST);
    $item->add($_POST);
} elseif (isset($_POST['update'])) {
    $item->check((int) $_POST['id'], UPDATE);
    $item->update($_POST);
} elseif (isset($_POST['delete'])) {
    $item->check((int) $_POST['id'], DELETE);
    $item->delete(['id' => (int) $_POST['id']], true);
} else {
    throw new \Glpi\Exception\Http\AccessDeniedHttpException();
}
Html::back();
