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

// Unit tests run without GLPI: load the plugin classes and stub the few GLPI helpers they use.
require dirname(__DIR__) . '/vendor/autoload.php';

if (!function_exists('__')) {
    function __(string $str, string $domain = 'glpi'): string
    {
        return $str;
    }
}
if (!function_exists('_n')) {
    function _n(string $sing, string $plural, int $nb, string $domain = 'glpi'): string
    {
        return $nb === 1 ? $sing : $plural;
    }
}
if (!function_exists('htmlescape')) {
    function htmlescape(string $str): string
    {
        return htmlspecialchars($str, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }
}

// GLPI rights constants (src/autoload/constants.php)
foreach (
    ['READ' => 1, 'UPDATE' => 2, 'CREATE' => 4, 'DELETE' => 8, 'PURGE' => 16, 'ALLSTANDARDRIGHT' => 31,
          'READNOTE' => 32, 'UPDATENOTE' => 64, 'READ_OWNED' => 1024, 'UPDATE_OWNED' => 2048] as $name => $value
) {
    if (!defined($name)) {
        define($name, $value);
    }
}
