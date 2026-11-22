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
 * Help content (data/help/{lang}.json): guides by role, glossary, legend of the matrix, contextual boxes, field help and
 * frequently asked questions. Pure logic: it only reads the JSON files that ship with the plugin.
 */
final class HelpContent
{
    /** Role guides, in display order; the first one is the fallback. */
    public const ROLES = ['analyst', 'owner', 'auditor', 'agent'];

    /** Pages a role task can link to (resolved by Help). */
    public const LINKS = ['matrix', 'search', 'positions', 'resources', 'grants', 'help', ''];

    /** Language of the content for a GLPI language code (es_AR, es_ES... use Spanish; anything else English). */
    public static function languageFor(string $glpiLanguage): string
    {
        return str_starts_with(strtolower($glpiLanguage), 'es') ? 'es' : 'en';
    }

    /**
     * @return array{roles: list<array<string,mixed>>, glossary: list<array<string,string>>, faq: list<array<string,string>>,
     *               legend: array<string,array<string,string>>, boxes: array<string,array<string,mixed>>, fields: array<string,string>}
     */
    public static function load(string $lang): array
    {
        $data = self::read($lang === 'es' ? 'es' : 'en') ?? self::read('en') ?? [];
        return [
            'roles'    => array_values((array) ($data['roles'] ?? [])),
            'glossary' => array_values((array) ($data['glossary'] ?? [])),
            'faq'      => array_values((array) ($data['faq'] ?? [])),
            'legend'   => (array) ($data['legend'] ?? []),
            'boxes'    => (array) ($data['boxes'] ?? []),
            'fields'   => (array) ($data['fields'] ?? []),
        ];
    }

    /**
     * Guide of a role; an unknown or missing role key gets the analyst guide.
     *
     * @param array{roles: list<array<string,mixed>>} $content
     *
     * @return array<string,mixed>
     */
    public static function forRole(array $content, ?string $roleKey): array
    {
        $fallback = [];
        foreach ($content['roles'] as $role) {
            if (($role['key'] ?? '') === $roleKey) {
                return $role;
            }
            if (($role['key'] ?? '') === self::ROLES[0]) {
                $fallback = $role;
            }
        }
        return $fallback;
    }

    /** @return array<string,mixed>|null */
    private static function read(string $lang): ?array
    {
        $file = dirname(__DIR__) . '/data/help/' . $lang . '.json';
        if (!is_readable($file)) {
            return null;
        }
        $data = json_decode((string) file_get_contents($file), true);
        return is_array($data) ? $data : null;
    }
}
