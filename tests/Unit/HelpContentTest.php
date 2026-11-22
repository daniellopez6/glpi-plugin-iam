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

namespace GlpiPlugin\Iam\Tests\Unit;

use GlpiPlugin\Iam\HelpContent;
use PHPUnit\Framework\TestCase;

final class HelpContentTest extends TestCase
{
    /** @param array<mixed> $a @return list<string> */
    private static function keyPaths(array $a, string $prefix = ''): array
    {
        $out = [];
        foreach ($a as $k => $v) {
            $path = $prefix . '/' . $k;
            $out[] = $path;
            if (is_array($v)) {
                $out = array_merge($out, self::keyPaths($v, $path));
            }
        }
        sort($out);
        return $out;
    }

    public function testEsAndEnHaveSameKeys(): void
    {
        $es = HelpContent::load('es');
        $en = HelpContent::load('en');
        self::assertSame(self::keyPaths($es), self::keyPaths($en));
        foreach (['roles', 'glossary', 'faq', 'legend', 'boxes', 'fields'] as $part) {
            self::assertNotEmpty($es[$part], $part);
        }
        self::assertSame(['analyst', 'owner', 'auditor', 'agent'], array_column($es['roles'], 'key'));
        self::assertGreaterThanOrEqual(8, count($es['faq']));
    }

    public function testEveryLegendStateDocumented(): void
    {
        $required = ['allowed', 'on_request', 'forbidden', 'none', 'ok', 'missing', 'unexpected', 'forbidden_held', 'privileged'];
        foreach (['es', 'en'] as $lang) {
            $legend = HelpContent::load($lang)['legend'];
            self::assertSame([], array_diff($required, array_keys($legend)), $lang);
            foreach ($legend as $key => $entry) {
                self::assertNotSame('', trim((string) ($entry['label'] ?? '')), "$lang $key label");
                self::assertNotSame('', trim((string) ($entry['text'] ?? '')), "$lang $key text");
            }
        }
    }

    public function testUnknownRoleFallsBackToAnalyst(): void
    {
        $content = HelpContent::load('en');
        self::assertSame('analyst', HelpContent::forRole($content, null)['key']);
        self::assertSame('analyst', HelpContent::forRole($content, 'nonsense')['key']);
        self::assertSame('owner', HelpContent::forRole($content, 'owner')['key']);
        self::assertSame('agent', HelpContent::forRole($content, 'agent')['key']);
    }

    public function testGlossaryEntriesHaveIsoControl(): void
    {
        $allowed = ['A.5.3', 'A.5.15', 'A.5.16', 'A.5.18', 'A.8.2'];
        foreach (['es', 'en'] as $lang) {
            $glossary = HelpContent::load($lang)['glossary'];
            self::assertGreaterThanOrEqual(10, count($glossary));
            foreach ($glossary as $entry) {
                self::assertContains($entry['iso'] ?? '', $allowed, $lang . ' ' . ($entry['term'] ?? '?'));
                self::assertNotSame('', trim((string) ($entry['definition'] ?? '')));
            }
        }
    }

    public function testUnknownLanguageFallsBackToEnglish(): void
    {
        self::assertSame(HelpContent::load('en'), HelpContent::load('fr'));
        self::assertSame('es', HelpContent::languageFor('es_AR'));
        self::assertSame('en', HelpContent::languageFor('en_GB'));
    }
}
