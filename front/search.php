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
use GlpiPlugin\Iam\CaseSearch;
use GlpiPlugin\Iam\Help;
use GlpiPlugin\Iam\Matrix;
use GlpiPlugin\Iam\Menu;
use GlpiPlugin\Iam\QuickSearch;

// Quick case search: one box for tickets (#1234), grants (G-123), waivers (EXC-…), people, resources and roles
if (!Matrix::canView()) {
    throw new \Glpi\Exception\Http\AccessDeniedHttpException();
}

$q = $_GET['q'] ?? '';
$q = is_string($q) ? trim(mb_substr($q, 0, 200)) : '';
$parsed = QuickSearch::parse($q);
$results = $q === '' ? null : CaseSearch::run($parsed);

Html::header(__('Case search', 'iam'), $_SERVER['PHP_SELF'], plugin_iam_sector(), Menu::class, 'search');
TemplateRenderer::getInstance()->display('@iam/search.html.twig', [
    'help'       => Help::context(),
    'q'          => $q,
    'results'    => $results,
    'parsed'     => $parsed,
    'limit'      => CaseSearch::LIMIT,
    'self_url'   => plugin_iam_url('front/search.php'),
    'user_links' => (bool) Session::haveRight('user', READ),
    'user_url'   => User::getFormURL(),
]);
Html::footer();
