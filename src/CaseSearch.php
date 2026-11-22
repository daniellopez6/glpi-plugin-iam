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

use Glpi\DBAL\QuerySubQuery;
use Profile_User;
use User;

/**
 * Data access of the quick case search. Every group goes through the visibility predicate of its own table
 * (Resource / Role / Grant ::visibilityCriteria()); people are limited to those the session may see and, for sessions
 * that see the register only through ownership, to the holders of a visible grant (owners never enumerate people).
 * User text only reaches SQL as a bound LIKE value, with the LIKE wildcards escaped so they match literally.
 */
final class CaseSearch
{
    public const LIMIT = 50;

    /** LIKE criterion matching $word literally anywhere (`%`, `_` and the backslash lose their special meaning). */
    /** @return array{0:string,1:string} */
    public static function like(string $word): array
    {
        return ['LIKE', '%' . addcslashes($word, '\\%_') . '%'];
    }

    /** @return list<string> */
    private static function words(string $text): array
    {
        return $text === '' ? [] : array_values(array_filter(explode(' ', $text), static fn (string $w): bool => $w !== ''));
    }

    /** @return array<mixed> */
    private static function userMatch(string $word, string $ut): array
    {
        return ['OR' => [["$ut.name" => self::like($word)], ["$ut.realname" => self::like($word)], ["$ut.firstname" => self::like($word)]]];
    }

    /** @return array<mixed> */
    private static function resourceMatch(string $word, string $rt): array
    {
        return ['OR' => [["$rt.name" => self::like($word)], ["$rt.code" => self::like($word)]]];
    }

    /**
     * @param array{tickets:list<int>, waivers:list<string>, grants:list<int>, text:string} $parsed
     *
     * @return array{users:list<array<string,mixed>>, resources:list<array<string,mixed>>, roles:list<array<string,mixed>>, grants:list<array<string,mixed>>, waivers:list<string>}
     */
    public static function run(array $parsed): array
    {
        $words = self::words($parsed['text']);
        $out = ['users' => [], 'resources' => [], 'roles' => [], 'grants' => [], 'waivers' => $parsed['waivers']];
        if (!Matrix::canView()) {
            return $out;
        }
        if ($words !== []) {
            $out['users'] = self::users($words);
            $out['resources'] = self::resources($words);
            $out['roles'] = self::roles($words);
        }
        if ($words !== [] || $parsed['tickets'] !== [] || $parsed['grants'] !== []) {
            $out['grants'] = self::grants($words, $parsed['tickets'], $parsed['grants']);
        }
        return $out;
    }

    /**
     * @param list<string> $words
     *
     * @return list<array<string,mixed>>
     */
    private static function users(array $words): array
    {
        global $DB;
        $ut = User::getTable();
        $where = ["$ut.is_deleted" => 0, "$ut.is_active" => 1];
        if (Position_User::canView()) {
            $put = Profile_User::getTable();
            $where["$ut.id"] = new QuerySubQuery([
                'SELECT' => "$put.users_id",
                'FROM'   => $put,
                'WHERE'  => getEntitiesRestrictCriteria($put, '', '', true),
            ]);
        } else {
            $gt = Grant::getTable();
            $where["$ut.id"] = new QuerySubQuery(['SELECT' => "$gt.users_id", 'FROM' => $gt, 'WHERE' => [Grant::visibilityCriteria()]]);
        }
        foreach ($words as $w) {
            $where[] = self::userMatch($w, $ut);
        }
        $rows = [];
        foreach ($DB->request(['SELECT' => ["$ut.id", "$ut.name", "$ut.realname", "$ut.firstname"], 'FROM' => $ut, 'WHERE' => $where, 'ORDER' => ["$ut.realname", "$ut.name"], 'LIMIT' => self::LIMIT]) as $r) {
            $rows[] = [
                'id'    => (int) $r['id'],
                'label' => formatUserName((int) $r['id'], (string) $r['name'], (string) $r['realname'], (string) $r['firstname']),
                'login' => (string) $r['name'],
            ];
        }
        return $rows;
    }

    /**
     * @param list<string> $words
     *
     * @return list<array<string,mixed>>
     */
    private static function resources(array $words): array
    {
        global $DB;
        $rt = Resource::getTable();
        $ot = Role::getTable();
        $where = [Resource::visibilityCriteria(), "$rt.is_deleted" => 0];
        foreach ($words as $w) {
            // a word may match the resource itself or one of its roles ("sap aprobador")
            $where[] = ['OR' => [
                self::resourceMatch($w, $rt),
                ["$rt.id" => new QuerySubQuery(['SELECT' => "$ot.plugin_iam_resources_id", 'FROM' => $ot, 'WHERE' => ["$ot.name" => self::like($w)]])],
            ]];
        }
        $rows = [];
        foreach ($DB->request(['SELECT' => ["$rt.id", "$rt.name", "$rt.code"], 'FROM' => $rt, 'WHERE' => $where, 'ORDER' => ["$rt.name"], 'LIMIT' => self::LIMIT]) as $r) {
            $rows[] = ['id' => (int) $r['id'], 'label' => (string) $r['name'], 'code' => (string) $r['code'], 'url' => Resource::getFormURLWithID((int) $r['id'])];
        }
        return $rows;
    }

    /**
     * @param list<string> $words
     *
     * @return list<array<string,mixed>>
     */
    private static function roles(array $words): array
    {
        global $DB;
        $ot = Role::getTable();
        $rt = Resource::getTable();
        $where = [Role::visibilityCriteria()];
        foreach ($words as $w) {
            $where[] = ['OR' => [
                ["$ot.name" => self::like($w)],
                self::resourceMatch($w, $rt),
            ]];
        }
        $rows = [];
        foreach (
            $DB->request([
            'SELECT'     => ["$ot.id", "$ot.name", "$rt.name AS resource_name"],
            'FROM'       => $ot,
            'INNER JOIN' => [$rt => ['ON' => [$ot => 'plugin_iam_resources_id', $rt => 'id']]],
            'WHERE'      => $where,
            'ORDER'      => ["$rt.name", "$ot.name"],
            'LIMIT'      => self::LIMIT,
            ]) as $r
        ) {
            $rows[] = ['id' => (int) $r['id'], 'label' => (string) $r['name'], 'resource' => (string) $r['resource_name'], 'url' => Role::getFormURLWithID((int) $r['id'])];
        }
        return $rows;
    }

    /**
     * @param list<string> $words
     * @param list<int>    $tickets
     * @param list<int>    $ids
     *
     * @return list<array<string,mixed>>
     */
    private static function grants(array $words, array $tickets, array $ids): array
    {
        global $DB;
        $gt = Grant::getTable();
        $rt = Resource::getTable();
        $ot = Role::getTable();
        $ut = User::getTable();
        $where = [Grant::visibilityCriteria()];
        if ($tickets !== [] || $ids !== []) {
            $or = [];
            if ($tickets !== []) {
                $or[] = ["$gt.tickets_id" => $tickets];
            }
            if ($ids !== []) {
                $or[] = ["$gt.id" => $ids];
            }
            $where[] = ['OR' => $or];
        }
        foreach ($words as $w) {
            $where[] = ['OR' => [
                self::userMatch($w, $ut),
                self::resourceMatch($w, $rt),
                ["$ot.name" => self::like($w)],
            ]];
        }
        $status = Grant::statusLabels();
        $rows = [];
        foreach (
            $DB->request([
            'SELECT'     => ["$gt.id", "$gt.status", "$gt.tickets_id", "$ut.id AS uid", "$ut.name AS login", "$ut.realname", "$ut.firstname", "$rt.name AS resource_name", "$ot.name AS role_name"],
            'FROM'       => $gt,
            'INNER JOIN' => [
                $rt => ['ON' => [$gt => 'plugin_iam_resources_id', $rt => 'id']],
                $ot => ['ON' => [$gt => 'plugin_iam_roles_id', $ot => 'id']],
            ],
            'LEFT JOIN'  => [$ut => ['ON' => [$gt => 'users_id', $ut => 'id']]],
            'WHERE'      => $where,
            'ORDER'      => ["$gt.id DESC"],
            'LIMIT'      => self::LIMIT,
            ]) as $r
        ) {
            $rows[] = [
                'id'       => (int) $r['id'],
                'person'   => formatUserName((int) $r['uid'], (string) $r['login'], (string) $r['realname'], (string) $r['firstname']),
                'resource' => (string) $r['resource_name'],
                'role'     => (string) $r['role_name'],
                'status'   => (string) ($status[$r['status']] ?? $r['status']),
                'ticket'   => (int) $r['tickets_id'],
                'url'      => Grant::getFormURLWithID((int) $r['id']),
            ];
        }
        return $rows;
    }
}
