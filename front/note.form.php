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

use GlpiPlugin\Iam\Note;

// Append-only log: the only action is adding an entry (POST, CSRF checked by GLPI). Notes are never shown, updated,
// deleted or purged through this page; they are read in the "Log (IAM)" tab of their item.
if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !isset($_POST['add'])) {
    throw new \Glpi\Exception\Http\AccessDeniedHttpException();
}
$item = new Note();
$item->check(-1, CREATE, $_POST);
$item->add($_POST);
Html::back();
