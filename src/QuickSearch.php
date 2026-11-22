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

namespace GlpiPlugin\Iam;

/**
 * Parser of the quick case search box (pure): identifiers are pulled out of the text, the rest stays free text.
 */
final class QuickSearch
{
    public const MAX_TEXT = 100;

    /**
     * @return array{tickets:list<int>, waivers:list<string>, grants:list<int>, text:string}
     */
    public static function parse(string $q): array
    {
        $tickets = [];
        $waivers = [];
        $grants = [];

        $q = (string) preg_replace_callback('/\bEXC-\d{4}-\d{3,}\b/i', static function (array $m) use (&$waivers): string {
            $waivers[] = strtoupper($m[0]);
            return ' ';
        }, $q);
        $q = (string) preg_replace_callback('/(?:#|\bticket:)\s?(\d{1,9})\b/i', static function (array $m) use (&$tickets): string {
            $tickets[] = (int) $m[1];
            return ' ';
        }, $q);
        $q = (string) preg_replace_callback('/(?:\bG-|\bgrant:)(\d{1,9})\b/i', static function (array $m) use (&$grants): string {
            $grants[] = (int) $m[1];
            return ' ';
        }, $q);

        $text = trim((string) preg_replace('/\s+/u', ' ', $q));
        $text = trim(mb_substr($text, 0, self::MAX_TEXT));

        return [
            'tickets' => array_values(array_unique($tickets)),
            'waivers' => array_values(array_unique($waivers)),
            'grants'  => array_values(array_unique($grants)),
            'text'    => $text,
        ];
    }
}
