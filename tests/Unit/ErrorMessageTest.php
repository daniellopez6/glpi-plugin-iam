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

use GlpiPlugin\Iam\ErrorMessage;
use GlpiPlugin\Iam\PositionPeriod;
use PHPUnit\Framework\TestCase;

final class ErrorMessageTest extends TestCase
{
    public function testFormatPrefixesTheCode(): void
    {
        self::assertSame('[date_order] The end date is wrong.', ErrorMessage::format('date_order', 'The end date is wrong.'));
    }

    public function testCombineKeepsEveryMessageOnce(): void
    {
        $a = ErrorMessage::format('a_code', 'A.');
        $b = ErrorMessage::format('b_code', 'B.');
        self::assertSame('[a_code] A. [b_code] B.', ErrorMessage::combine([$a, $b, $a]));
        self::assertSame('', ErrorMessage::combine([]));
    }

    public function testAgentAssignmentNeedsTicket(): void
    {
        self::assertSame(['agent_requires_ticket'], PositionPeriod::agentErrors(['tickets_id' => 0], 'agent'));
        self::assertSame(['agent_requires_ticket'], PositionPeriod::agentErrors([], 'agent'));
        self::assertSame([], PositionPeriod::agentErrors(['tickets_id' => 47], 'agent'));
        self::assertSame([], PositionPeriod::agentErrors(['tickets_id' => 0], 'analyst'));
        self::assertSame([], PositionPeriod::agentErrors(['tickets_id' => 0], null));
    }
}
