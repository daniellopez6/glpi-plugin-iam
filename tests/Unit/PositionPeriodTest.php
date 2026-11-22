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

use GlpiPlugin\Iam\PositionPeriod;
use PHPUnit\Framework\TestCase;

final class PositionPeriodTest extends TestCase
{
    private const TODAY = '2026-11-22';

    public function testOpenEndedIsActive(): void
    {
        $this->assertTrue(PositionPeriod::isActive(null, null, self::TODAY));
        $this->assertTrue(PositionPeriod::isActive('2026-01-01', null, self::TODAY));
        $this->assertTrue(PositionPeriod::isActive('2026-11-22', '2026-11-22', self::TODAY));
    }

    public function testEndedYesterdayIsInactive(): void
    {
        $this->assertFalse(PositionPeriod::isActive('2026-01-01', '2026-11-21', self::TODAY));
    }

    public function testFutureBeginIsInactive(): void
    {
        $this->assertFalse(PositionPeriod::isActive('2026-11-23', null, self::TODAY));
    }

    public function testEndBeforeBeginRejected(): void
    {
        $input = ['type' => 'holder', 'is_primary' => 0, 'date_begin' => '2026-05-10', 'date_end' => '2026-05-09'];
        $this->assertSame(['date_order'], PositionPeriod::validate($input, [], self::TODAY));
    }

    public function testSecondActivePrimaryRejected(): void
    {
        $other = [['is_primary' => 1, 'date_begin' => '2026-01-01', 'date_end' => null]];
        $input = ['type' => 'holder', 'is_primary' => 1, 'date_begin' => '2026-06-01', 'date_end' => null];
        $this->assertSame(['primary_duplicate'], PositionPeriod::validate($input, $other, self::TODAY));
    }

    public function testEndedPrimaryDoesNotConflict(): void
    {
        $other = [['is_primary' => 1, 'date_begin' => '2025-01-01', 'date_end' => '2026-01-01']];
        $input = ['type' => 'holder', 'is_primary' => 1, 'date_begin' => '2026-06-01', 'date_end' => null];
        $this->assertSame([], PositionPeriod::validate($input, $other, self::TODAY));
    }

    public function testSubstituteMayOverlapPrimary(): void
    {
        $other = [['is_primary' => 1, 'date_begin' => '2026-01-01', 'date_end' => null]];
        $input = ['type' => 'substitute', 'is_primary' => 0, 'date_begin' => '2026-06-01', 'date_end' => null];
        $this->assertSame([], PositionPeriod::validate($input, $other, self::TODAY));
    }

    public function testTypeInvalid(): void
    {
        $input = ['type' => 'boss', 'is_primary' => 0, 'date_begin' => null, 'date_end' => null];
        $this->assertSame(['type_invalid'], PositionPeriod::validate($input, [], self::TODAY));
    }

    public function testMalformedDatesRejected(): void
    {
        foreach (['2026-13-01', '2026-02-30', '22/11/2026', 'abc', '2026-1-1', "2026-11-22' OR 1=1"] as $bad) {
            $this->assertSame(['date_invalid'], PositionPeriod::validate(
                ['type' => 'holder', 'is_primary' => 0, 'date_begin' => $bad, 'date_end' => null],
                [],
                self::TODAY
            ), $bad);
            $this->assertSame(['date_invalid'], PositionPeriod::validate(
                ['type' => 'holder', 'is_primary' => 0, 'date_begin' => null, 'date_end' => $bad],
                [],
                self::TODAY
            ), $bad);
        }
    }

    public function testEmptyDatesAreOpen(): void
    {
        $input = ['type' => 'temporary', 'is_primary' => 0, 'date_begin' => '', 'date_end' => ''];
        $this->assertSame([], PositionPeriod::validate($input, [], self::TODAY));
    }
}
