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

use CommonGLPI;
use Glpi\Application\View\TemplateRenderer;

/**
 * "Help and glossary" page and the contextual help of every screen (collapsible boxes and field tooltips).
 * The content comes from HelpContent; everything is escaped by Twig.
 */
class Help extends CommonGLPI
{
    public static function getTypeName($nb = 0)
    {
        return __('Help and glossary', 'iam');
    }

    public static function getMenuName()
    {
        return self::getTypeName();
    }

    public static function getIcon(): string
    {
        return 'ti ti-help';
    }

    /** Anyone who can open some IAM page can read the help. */
    public static function canView(): bool
    {
        return Rights::hasAny();
    }

    public static function getSearchURL($full = true)
    {
        return plugin_iam_url('front/help.php', $full);
    }

    /**
     * Content in the language of the session.
     *
     * @return array{roles: list<array<string,mixed>>, glossary: list<array<string,string>>, faq: list<array<string,string>>,
     *               legend: array<string,array<string,string>>, boxes: array<string,array<string,mixed>>, fields: array<string,string>}
     */
    public static function content(): array
    {
        return HelpContent::load(HelpContent::languageFor((string) ($_SESSION['glpilanguage'] ?? 'en_GB')));
    }

    /**
     * Contextual help handed to the templates: collapsible boxes, field tooltips and the matrix legend.
     *
     * @return array{boxes: array<string,array<string,mixed>>, fields: array<string,string>, legend: array<string,array<string,string>>}
     */
    public static function context(): array
    {
        $content = self::content();
        return ['boxes' => $content['boxes'], 'fields' => $content['fields'], 'legend' => $content['legend']];
    }

    /** Prints a collapsible "What is this?" box (for screens that GLPI renders itself, e.g. the position form). */
    public static function box(string $key): void
    {
        TemplateRenderer::getInstance()->display('@iam/_help.html.twig', ['box' => self::content()['boxes'][$key] ?? null]);
    }

    /**
     * Pages a task of a role guide can link to, only the ones the session can open.
     *
     * @return array<string,string>
     */
    private static function links(): array
    {
        $links = ['help' => self::getSearchURL()];
        if (Matrix::canView()) {
            $links['matrix'] = Menu::getSearchURL();
            $links['search'] = plugin_iam_url('front/search.php');
        }
        if (Position::canView()) {
            $links['positions'] = Position::getSearchURL();
        }
        if (Resource::canView()) {
            $links['resources'] = Resource::getSearchURL();
        }
        if (Grant::canView()) {
            $links['grants'] = Grant::getSearchURL();
        }
        return $links;
    }

    public static function show(): void
    {
        $content = self::content();
        $current = Rights::activeRoleKey();
        $mine = HelpContent::forRole($content, $current);
        $others = array_values(array_filter($content['roles'], static fn (array $r): bool => $r['key'] !== $mine['key']));
        TemplateRenderer::getInstance()->display('@iam/help.html.twig', [
            'mine'     => $mine,
            'others'   => $others,
            'glossary' => $content['glossary'],
            'faq'      => $content['faq'],
            'legend'   => $content['legend'],
            'links'    => self::links(),
        ]);
    }
}
