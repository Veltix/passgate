<?php

/**
 * PassGate - Secure your password using password Gate.
 *
 * @author    Kristen Lõoke <kristen@neti.ee>
 * @copyright    Copyright (c) Kristen Lõoke
 */

namespace Hmer\PassGate;

/**
 * Class PassGate.
 */
class PassGate
{
    protected const MAX_LENGTH_ARGON2ID = 72;
    protected static string $algoArgon2id = 'argon2id'; // by default use ARGON2ID
    protected static array $optionsArgon2id = [
        'memory_cost' => 1024, // PASSWORD_ARGON2_DEFAULT_MEMORY_COST
        'time_cost'   => 2, // PASSWORD_ARGON2_DEFAULT_TIME_COST
        'threads'     => 2, // PASSWORD_ARGON2_DEFAULT_THREADS
    ];

    protected static string $characters = '!"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ' .
    '[\]^_`abcdefghijklmnopqrstuvwxyz{|}~';

    /**
     * @param string $password
     *
     * @throws PassGateException
     *
     * @return string
     */
    public static function hash(string $password): string
    {
        $string = null;

        try {
            if (static::$algoArgon2id) {
                $string = \password_hash($password, static::$algoArgon2id, static::$optionsArgon2id);
            }
        } catch (\Exception $e) {
            if ($e->getMessage() === 'Password too long') {
                throw new PassGateException(
                    \sprintf(
                        'Password too long (%d max): %d chars',
                        self::MAX_LENGTH_ARGON2ID,
                        \mb_strlen($password)
                    )
                );
            }
            throw new PassGateException('Hash Failure');
        }

        return $string;
    }

    /**
     * @param string $password
     * @param string $hash
     *
     * @return bool
     */
    public static function verify(string $password, string $hash): bool
    {
        return \password_verify($password, $hash);
    }

    /**
     * @param string $hash
     *
     * @return bool
     */
    public static function needsRehash(string $hash): bool
    {
        if (static::$algoArgon2id) {
            return \password_needs_rehash($hash, static::$algoArgon2id, static::$optionsArgon2id);
        }
    }

    /**
     * @param int $length
     *
     * @throws \Exception
     *
     * @return string
     */
    public static function getRandomString(int $length = 64): string
    {
        $string = '';
        $countCharacters = \mb_strlen(static::$characters) - 1;

        for ($i = 0; $i < $length; ++$i) {
            $string .= static::$characters[\random_int(0, $countCharacters)];
        }

        return $string;
    }

    /**
     * @param string $characters
     */
    public static function setCharactersForRandomString(string $characters): void
    {
        static::$characters = $characters;
    }

    /**
     * @return string
     */
    public static function getCharactersForRandomString(): string
    {
        return static::$characters;
    }
}