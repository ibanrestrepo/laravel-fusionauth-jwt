<?php

namespace DaniloPolani\FusionAuthJwt;

use App\User;
use CoreGateway\User\UserRepository;
use Illuminate\Contracts\Auth\Authenticatable;

/**
 * @property-read string $applicationId
 * @property-read string $authenticationType
 * @property-read string $aud
 * @property-read string $iss
 * @property-read string $sub
 * @property-read string $jti
 * @property-read string $scope
 * @property-read string $email
 * @property-read bool $email_verified
 * @property-read array<string> $roles
 * @property-read int $exp
 * @property-read int $iat
 */
class FusionAuthJwtUser implements Authenticatable
{
    private array $userInfo;
    private $localUserInfo;

    /**
     * FusionAuthUser constructor.
     *
     * @param array $userInfo
     */
    public function __construct(array $userInfo)
    {
        $this->userInfo = $userInfo;
        // Get corresponding coreauth user
        $coregatewayUser = User::where(['username' => $userInfo['username']])->first();
        // This will throw an exception if the user was NOT found
        $this->localUserInfo = $coregatewayUser ?? false;
    }

    /**
     * {@inheritDoc}
     */
    public function getAuthIdentifierName()
    {
        return $this->userInfo['username'];
    }

    /**
     * {@inheritDoc}
     */
    public function getAuthIdentifier()
    {
        return $this->localUserInfo->id;
    }

    /**
     * {@inheritDoc}
     */
    public function getAuthPassword()
    {
        return '';
    }

    /**
     * {@inheritDoc}
     */
    public function getRememberToken()
    {
        return '';
    }

    /**
     * {@inheritDoc}
     */
    public function setRememberToken($value)
    {
        //
    }

    /**
     * {@inheritDoc}
     */
    public function getRememberTokenName()
    {
        return '';
    }

    /**
     * Get the whole user info array.
     *
     * @return array
     */
    public function getUserInfo(): array
    {
        return $this->userInfo;
    }

    public function getLocalUserInfo() {
        return $this->localUserInfo;
    }

    /**
     * Add a generic getter to get all the properties of the userInfo.
     *
     * @param  string $name
     * @return mixed the related value or null if not found
     */
    public function __get($name)
    {
        return $this->userInfo[$name] ?? $this->localUserInfo->{$name} ?? null;
    }

    /**
     * Stringify the current user.
     *
     * @return string
     */
    public function __toString()
    {
        return json_encode([$this->userInfo, 'localUser' => $this->localUserInfo]);
    }
}
