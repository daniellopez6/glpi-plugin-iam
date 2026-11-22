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

use PHPUnit\Framework\TestCase;

/** The version declared in setup.php must match the first release listed in plugin.xml. */
final class VersionTest extends TestCase
{
    public function testVersionMatchesPluginXml(): void
    {
        $root  = dirname(__DIR__, 2);
        $setup = file_get_contents($root . '/setup.php');
        $this->assertNotFalse($setup, 'setup.php must exist');
        $this->assertSame(
            1,
            preg_match("/define\\('PLUGIN_IAM_VERSION',\\s*'([^']+)'\\)/", $setup, $m),
            'PLUGIN_IAM_VERSION literal not found in setup.php'
        );

        $xml = simplexml_load_file($root . '/plugin.xml');
        $this->assertNotFalse($xml, 'plugin.xml must exist and be valid XML');
        $this->assertSame((string) $xml->versions->version[0]->num, $m[1]);
        $this->assertSame('1.0.0', $m[1]);
    }
}
