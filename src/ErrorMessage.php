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
 * Stable error messages (spec 13 bis): every refusal of the plugin starts with its code between brackets, so an API
 * client can react to the code whatever the language of the text. Only the text part is translated.
 */
final class ErrorMessage
{
    /** "[code] text". */
    public static function format(string $code, string $text): string
    {
        return '[' . $code . '] ' . $text;
    }

    /**
     * All the refusals of one operation in a single message (the REST API only reports one message per response).
     *
     * @param list<string> $messages already formatted
     */
    public static function combine(array $messages): string
    {
        return implode(' ', array_values(array_unique($messages)));
    }
}
