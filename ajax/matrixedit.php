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

use GlpiPlugin\Iam\Matrix;
use GlpiPlugin\Iam\Position_Role;
use Symfony\Component\HttpFoundation\JsonResponse;

// Edit mode of the matrix: sets (or removes) the expectation of a position on a role. POST only; the GLPI kernel
// rejects cross-site POSTs (CSRF: Sec-Fetch-Site / Origin) before this script runs. Answers JSON.
// JsonResponse encodes with JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT
$reply = static function (int $status, bool $ok, ?string $expectation, string $message, ?array $counts = null): JsonResponse {
    $response = new JsonResponse(['ok' => $ok, 'expectation' => $expectation, 'message' => $message, 'counts' => $counts], $status);
    $response->headers->set('Cache-Control', 'no-store');
    return $response;
};

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    $response = $reply(405, false, null, __('Method not allowed.', 'iam'));
    $response->headers->set('Allow', 'POST');
    return $response;
}
if (!Matrix::canView() || !Matrix::canEdit()) {
    return $reply(403, false, null, __('You are not allowed to edit the matrix.', 'iam'));
}

$positionId = (int) ($_POST['position'] ?? 0);
$roleId = (int) ($_POST['role'] ?? 0);
$expectation = (string) ($_POST['expectation'] ?? '');
if ($positionId <= 0 || $roleId <= 0 || ($expectation !== '' && !in_array($expectation, Position_Role::EXPECTATIONS, true))) {
    return $reply(400, false, null, __('The expectation is not valid.', 'iam'));
}

// upsert() checks CONFIG UPDATE and write access on the row (position visible, role's resource writable) again
$saved = Position_Role::upsert($positionId, $roleId, $expectation === '' ? null : $expectation);
$message = Matrix::takeMessages();
$cell = Matrix::cell($positionId, $roleId);
if (!$saved) {
    // 403 when the session cannot even see the cell; otherwise the refusal comes from the business rules
    return $reply(
        $cell === null ? 403 : 422,
        false,
        $cell['expectation'] ?? null,
        $message !== '' ? $message : __('The matrix cell could not be saved.', 'iam'),
        $cell['counts'] ?? null
    );
}
return $reply(200, true, $cell['expectation'] ?? null, __('Matrix cell saved.', 'iam'), $cell['counts'] ?? null);
