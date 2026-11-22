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

/**
 * IAM - Identity & Access Governance plugin for GLPI.
 * Role-based access governance (RBAC matrix, access register, deviations, recertification).
 * Licencia GPL-3.0-or-later.
 */

use GlpiPlugin\Iam\Profile;

define('PLUGIN_IAM_VERSION', '1.0.0');
define('PLUGIN_IAM_MIN_GLPI', '12.0.0');
define('PLUGIN_IAM_MAX_GLPI', '12.99.99');

function plugin_init_iam(): void
{
    global $PLUGIN_HOOKS;

    $PLUGIN_HOOKS['csrf_compliant']['iam'] = true;

    if (!Plugin::isPluginActive('iam')) {
        return;
    }

    Plugin::registerClass(Profile::class, ['addtabon' => ['Profile']]);
}

/**
 * @return array<string,mixed>
 */
function plugin_version_iam(): array
{
    return [
        'name'         => __('IAM - Identity & Access Governance', 'iam'),
        'version'      => PLUGIN_IAM_VERSION,
        'author'       => 'daniellopez6',
        'license'      => 'GPL-3.0-or-later',
        'homepage'     => 'https://github.com/daniellopez6/glpi-plugin-iam',
        'requirements' => [
            'glpi' => ['min' => PLUGIN_IAM_MIN_GLPI, 'max' => PLUGIN_IAM_MAX_GLPI],
            'php'  => ['min' => '8.2'],
        ],
    ];
}

/**
 * Plugin options: do not run the installation automatically when downloaded from the Marketplace.
 *
 * @return array<string,mixed>
 */
function plugin_iam_options(): array
{
    return [Plugin::OPTION_AUTOINSTALL_DISABLED => true];
}

function plugin_iam_check_prerequisites(): bool
{
    return true;
}

function plugin_iam_check_config(bool $verbose = false): bool
{
    return true;
}
