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

use Glpi\Application\View\TemplateRenderer;
use GlpiPlugin\Iam\Matrix;
use GlpiPlugin\Iam\Position_Role;
use GlpiPlugin\Iam\Role;

// Nominal panel of one matrix cell (HTML fragment). Read-only: GET only.
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'GET') {
    throw new \Symfony\Component\HttpKernel\Exception\MethodNotAllowedHttpException(['GET']);
}
// Rights and visibility of the position AND the role's resource are checked again here (403 otherwise)
$cell = Matrix::canView()
    ? Matrix::cell((int) ($_GET['position'] ?? -1), (int) ($_GET['role'] ?? 0))
    : null;
if ($cell === null) {
    throw new \Glpi\Exception\Http\AccessDeniedHttpException();
}

header('Content-Type: text/html; charset=UTF-8');
header('Cache-Control: no-store');
TemplateRenderer::getInstance()->display('@iam/matrix_cell.html.twig', $cell + [
    'members_visible' => Matrix::membersVisible(),
    'expectations'    => Position_Role::expectationLabels(),
    'levels'          => Role::levelLabels(),
    'states'          => Matrix::stateLabels(),
]);
