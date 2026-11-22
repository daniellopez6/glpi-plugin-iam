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
use GlpiPlugin\Iam\MatrixBuilder;
use GlpiPlugin\Iam\Menu;
use GlpiPlugin\Iam\Position_Role;
use GlpiPlugin\Iam\Role;

// RBAC matrix: positions x resources (expandable to roles), deviations at a glance (spec §11.1)
if (!Matrix::canView()) {
    throw new \Glpi\Exception\Http\AccessDeniedHttpException();
}

$area = max(0, (int) ($_GET['area'] ?? 0));
$resource = max(0, (int) ($_GET['resource'] ?? 0));
$onlyDeviations = (int) ($_GET['only_deviations'] ?? 0) === 1;
$privileged = (int) ($_GET['privileged'] ?? 0) === 1;

$data = Matrix::load($area, $resource, $privileged, $onlyDeviations);
$model = $data['model'];
$summary = $data['summary'];

$cols = [];
$clientCols = [];
foreach ($model['cols'] as $col) {
    $resId = (int) $col['resource_id'];
    $cols[] = [
        'id'         => $resId,
        'name'       => $col['resource'],
        'roles'      => count($col['roles']),
        'privileged' => count(array_filter($col['roles'], static fn (array $r): bool => $r['level'] === 'privileged')),
        'deviations' => $summary['resources'][$resId]['deviations'] ?? 0,
        'missing'    => $summary['resources'][$resId]['missing'] ?? 0,
    ];
    $clientCols[] = [
        $resId,
        array_map(
            static fn (array $r): array => [$r['id'], $r['name'], $r['level'], isset($data['breakglass'][$r['id']]) ? 1 : 0],
            $col['roles']
        ),
    ];
}

$blocksOf = static function (int $pos) use ($cols, $summary): array {
    $blocks = [];
    foreach ($cols as $c) {
        $blocks[] = $summary['blocks'][$pos . ':' . $c['id']] ?? null;
    }
    return $blocks;
};
$groups = [];
foreach ($model['rows'] as $row) {
    $last = array_key_last($groups);
    if ($last === null || $groups[$last]['area'] !== $row['area']) {
        $groups[] = ['area' => $row['area'], 'rows' => []];
        $last = array_key_last($groups);
    }
    $groups[$last]['rows'][] = [
        'id'         => $row['id'],
        'name'       => $row['name'],
        'deviations' => $summary['rows'][$row['id']]['deviations'] ?? 0,
        'missing'    => $summary['rows'][$row['id']]['missing'] ?? 0,
        'blocks'     => $blocksOf($row['id']),
    ];
}
$bucket = ($summary['rows'][MatrixBuilder::NO_POSITION]['deviations'] ?? 0) > 0
    ? ['deviations' => $summary['rows'][MatrixBuilder::NO_POSITION]['deviations'], 'blocks' => $blocksOf(MatrixBuilder::NO_POSITION)]
    : null;

$client = [
    'cols'  => $clientCols,
    'cells' => (object) $data['client'],
    'edit'  => Matrix::canEdit(),
    'members' => Matrix::membersVisible(),
    'i18n'  => [
        'a'          => __('Allowed', 'iam'),
        'r'          => __('On request', 'iam'),
        'f'          => __('Forbidden', 'iam'),
        ''           => __('No expectation', 'iam'),
        'holding'    => __('People holding it as expected', 'iam'),
        'expected'   => __('People expected to hold it', 'iam'),
        'unexpected' => __('Held without expectation', 'iam'),
        'forbidden'  => __('Held while forbidden', 'iam'),
        'missing'    => __('Expected, not granted', 'iam'),
        'privileged' => __('Privileged role', 'iam'),
        'breakglass' => __('Break-glass role', 'iam'),
        'saved'      => __('Matrix cell saved. Totals are refreshed when the page is reloaded.', 'iam'),
        'failed'     => __('The matrix cell could not be saved.', 'iam'),
        'set'        => __('Set the expectation', 'iam'),
        'loading'    => __('Loading…', 'iam'),
        'panelError' => __('The people of this cell could not be loaded.', 'iam'),
    ],
];
$json = json_encode($client, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_THROW_ON_ERROR);

$entityId = Session::getActiveEntity();

Html::header(__('Access matrix', 'iam'), $_SERVER['PHP_SELF'], plugin_iam_sector(), Menu::class, 'matrix');
TemplateRenderer::getInstance()->display('@iam/matrix.html.twig', [
    'groups'          => $groups,
    'bucket'          => $bucket,
    'cols'            => $cols,
    'totals'          => $summary['totals'],
    'counts'          => ['rows' => count($model['rows']), 'cols' => count($cols), 'roles' => array_sum(array_column($cols, 'roles'))],
    'areas'           => $data['areas'],
    'resources'       => $data['resources'],
    'filters'         => ['area' => $area, 'resource' => $resource, 'only_deviations' => $onlyDeviations, 'privileged' => $privileged],
    'entity'          => (string) Dropdown::getDropdownName('glpi_entities', $entityId),
    'recursive'       => (bool) ($_SESSION['glpiactive_entity_recursive'] ?? false),
    'members_visible' => Matrix::membersVisible(),
    'can_edit'        => Matrix::canEdit(),
    'expectations'    => Position_Role::expectationLabels(),
    'levels'          => Role::levelLabels(),
    'self_url'        => plugin_iam_url('front/matrix.php'),
    'cell_url'        => plugin_iam_url('ajax/matrixcell.php'),
    'edit_url'        => plugin_iam_url('ajax/matrixedit.php'),
    'client_json'     => $json,
]);
Html::footer();
