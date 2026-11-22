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

use GlpiPlugin\Iam\Install\Schema;
use GlpiPlugin\Iam\Scope;
use PHPUnit\Framework\TestCase;

/**
 * Parity guard: every plugin table that has a class is covered by the visibility hook (Scope::criteriaFor), and a
 * table without coverage has no class yet. Adding a class for a deferred table makes this test fail until the class
 * gets its visibility predicate.
 */
final class ScopeTest extends TestCase
{
    private static function classFile(string $class): string
    {
        $short = substr($class, strlen('GlpiPlugin\\Iam\\'));
        return dirname(__DIR__, 2) . '/src/' . str_replace('\\', '/', $short) . '.php';
    }

    public function testEveryTableIsCoveredOrDeferred(): void
    {
        $tables = array_keys(Schema::scope());
        $covered = array_keys(Scope::COVERED);
        $deferred = Scope::DEFERRED_TABLES;
        $this->assertSame([], array_intersect($covered, $deferred));
        $both = array_merge($covered, $deferred);
        sort($both);
        sort($tables);
        $this->assertSame($tables, $both);
    }

    public function testCoveredTablesHaveTheirClass(): void
    {
        foreach (Scope::COVERED as $table => $class) {
            $this->assertFileExists(self::classFile($class), $table);
            $this->assertStringStartsWith('GlpiPlugin\\Iam\\', $class);
        }
        $this->assertSame(array_values(Scope::COVERED), Scope::coveredItemtypes());
        $this->assertCount(7, Scope::coveredItemtypes());
    }

    public function testDeferredTablesHaveNoClassYet(): void
    {
        $classes = array_map(
            static fn (string $f): string => strtolower(basename($f, '.php')),
            glob(dirname(__DIR__, 2) . '/src/*.php') ?: []
        );
        foreach (Scope::DEFERRED_TABLES as $table) {
            $base = substr($table, strlen(Schema::PREFIX));
            // GLPI table name = class name lowercased and pluralised (deviations -> Deviation, campaignitems -> CampaignItem)
            $this->assertNotContains(rtrim($base, 's'), $classes, "$table has a class: cover it in Scope::criteriaFor()");
        }
    }

    public function testEveryCoveredItemtypeHasAPredicate(): void
    {
        $handled = Scope::HANDLED;
        $covered = Scope::coveredItemtypes();
        sort($handled);
        sort($covered);
        $this->assertSame($covered, $handled);
    }

    public function testCriteriaGuardFailsClosed(): void
    {
        $this->assertTrue(Scope::isHandled('A', ['A', 'B'], ['A']));
        $this->assertFalse(Scope::isHandled('Computer', ['A', 'B'], ['A']));
        $this->expectException(\LogicException::class);
        Scope::isHandled('B', ['A', 'B'], ['A']);
    }
}
