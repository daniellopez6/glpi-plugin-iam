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

use GlpiPlugin\Iam\Grant;
use GlpiPlugin\Iam\NoteRules;
use GlpiPlugin\Iam\Position_User;
use GlpiPlugin\Iam\Resource;
use PHPUnit\Framework\TestCase;

final class NoteRulesTest extends TestCase
{
    private const NOW = '2026-11-22 10:00:00';

    /** @return array<string,mixed> */
    private static function input(array $extra = []): array
    {
        return $extra + ['itemtype' => Grant::class, 'items_id' => 7, 'content' => 'Approved by the owner'];
    }

    public function testTargets(): void
    {
        $this->assertSame([Grant::class, Resource::class, Position_User::class], NoteRules::TARGETS);
    }

    public function testUnknownTargetRejected(): void
    {
        $this->assertFalse(NoteRules::prepareAdd(self::input(['itemtype' => 'User']), 5, self::NOW));
        $this->assertContains('target_invalid', NoteRules::errors(self::input(['itemtype' => 'User'])));
        // Exact class names only: no case variants, leading backslash or non-string values
        $this->assertFalse(NoteRules::prepareAdd(self::input(['itemtype' => strtolower(Grant::class)]), 5, self::NOW));
        $this->assertFalse(NoteRules::prepareAdd(self::input(['itemtype' => '\\' . Grant::class]), 5, self::NOW));
        $this->assertFalse(NoteRules::prepareAdd(self::input(['itemtype' => [Grant::class]]), 5, self::NOW));
        $this->assertFalse(NoteRules::prepareAdd(self::input(['items_id' => 0]), 5, self::NOW));
    }

    public function testEmptyContentRejected(): void
    {
        $this->assertFalse(NoteRules::prepareAdd(self::input(['content' => "  \n"]), 5, self::NOW));
        $this->assertContains('content_empty', NoteRules::errors(self::input(['content' => "  \n"])));
        $this->assertFalse(NoteRules::prepareAdd(['itemtype' => Grant::class, 'items_id' => 7], 5, self::NOW));
    }

    public function testContentTooLongRejected(): void
    {
        $max = str_repeat('é', NoteRules::MAX_LENGTH);
        $this->assertSame([], NoteRules::errors(self::input(['content' => $max])));
        $this->assertIsArray(NoteRules::prepareAdd(self::input(['content' => $max]), 5, self::NOW));
        $this->assertContains('content_too_long', NoteRules::errors(self::input(['content' => $max . 'x'])));
        $this->assertFalse(NoteRules::prepareAdd(self::input(['content' => $max . 'x']), 5, self::NOW));
    }

    public function testContentTrimmed(): void
    {
        $out = NoteRules::prepareAdd(self::input(['content' => "  line 1\nline 2 \n"]), 5, self::NOW);
        $this->assertIsArray($out);
        $this->assertSame("line 1\nline 2", $out['content']);
    }

    public function testAuthorAndDateFromServer(): void
    {
        $out = NoteRules::prepareAdd(self::input(['users_id' => 99, 'date_creation' => '2000-01-01']), 5, self::NOW);
        $this->assertIsArray($out);
        $this->assertSame(5, $out['users_id']);
        $this->assertSame(self::NOW, $out['date_creation']);
    }

    public function testExtraFieldsDropped(): void
    {
        $out = NoteRules::prepareAdd(self::input(['entities_id' => 3, 'id' => 44, 'date_mod' => '2000-01-01']), 5, self::NOW);
        $this->assertIsArray($out);
        $this->assertSame(
            ['itemtype', 'items_id', 'content', 'plugin_iam_notes_id', 'users_id', 'date_creation'],
            array_keys($out)
        );
        $this->assertSame(Grant::class, $out['itemtype']);
        $this->assertSame(7, $out['items_id']);
        $this->assertSame(0, $out['plugin_iam_notes_id']);
    }

    public function testCorrectionReferenceKept(): void
    {
        $out = NoteRules::prepareAdd(self::input(['plugin_iam_notes_id' => '12']), 5, self::NOW);
        $this->assertIsArray($out);
        $this->assertSame(12, $out['plugin_iam_notes_id']);
    }

    public function testCorrectionSameTarget(): void
    {
        $this->assertTrue(NoteRules::sameTarget(['itemtype' => Grant::class, 'items_id' => 7], Grant::class, 7));
        $this->assertFalse(NoteRules::sameTarget(['itemtype' => Grant::class, 'items_id' => 8], Grant::class, 7));
        $this->assertFalse(NoteRules::sameTarget(['itemtype' => Resource::class, 'items_id' => 7], Grant::class, 7));
    }

    public function testTargetCriteriaSelectsTheNotesOfOneTarget(): void
    {
        // Used by the log tab and by Resource::dependencyCount() (a resource with notes is never purged)
        $this->assertSame(['itemtype' => Resource::class, 'items_id' => 3], NoteRules::targetCriteria(Resource::class, 3));
        $this->assertSame(['itemtype' => Grant::class, 'items_id' => 7], NoteRules::targetCriteria(Grant::class, 7));
    }
}
