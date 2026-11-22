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

use GlpiPlugin\Iam\QuickSearch;
use PHPUnit\Framework\TestCase;

final class QuickSearchTest extends TestCase
{
    public function testTicketHash(): void
    {
        $p = QuickSearch::parse('#1234');
        self::assertSame([1234], $p['tickets']);
        self::assertSame('', $p['text']);
    }

    public function testTicketPrefix(): void
    {
        self::assertSame([77], QuickSearch::parse('ticket:77')['tickets']);
    }

    public function testWaiverCode(): void
    {
        $p = QuickSearch::parse('exc-2026-001');
        self::assertSame(['EXC-2026-001'], $p['waivers']);
        self::assertSame('', $p['text']);
    }

    public function testGrantCode(): void
    {
        self::assertSame([123], QuickSearch::parse('G-123')['grants']);
        self::assertSame([5], QuickSearch::parse('grant:5')['grants']);
    }

    public function testMixedQuery(): void
    {
        $p = QuickSearch::parse('#12 sap aprobador');
        self::assertSame([12], $p['tickets']);
        self::assertSame('sap aprobador', $p['text']);
    }

    public function testTextTruncatedAndNormalized(): void
    {
        $p = QuickSearch::parse("  a   b\t c  ");
        self::assertSame('a b c', $p['text']);
        self::assertSame(100, mb_strlen(QuickSearch::parse(str_repeat('x', 300))['text']));
    }

    public function testSqlMetacharactersStayText(): void
    {
        $p = QuickSearch::parse("  ' OR 1=1 --  ");
        self::assertSame("' OR 1=1 --", $p['text']);
        self::assertSame([], $p['tickets']);
        self::assertSame([], $p['grants']);
    }
}
