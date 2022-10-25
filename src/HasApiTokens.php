<?php

namespace DaniloPolani\FusionAuthJwt;

use Carbon\Carbon;
use DaniloPolani\FusionAuthJwt\Exceptions\InvalidTokenException;
use FusionAuth\FusionAuthClient;
use Illuminate\Support\Facades\Auth;
use Illuminate\Container\Container;
use Illuminate\Support\Str;
use Firebase\JWT\JWT;
use Laravel\Passport\Client;
use Laravel\Passport\Passport;

trait HasApiTokens
{
    /**
     * The current access token for the authentication user.
     *
     * @var Token
     */
    protected $accessToken;

    /**
     * Get all of the user's registered OAuth clients.
     *
     * @return \Illuminate\Database\Eloquent\Relations\HasMany
     */
    public function clients()
    {
        return $this->hasMany(Passport::clientModel(), 'user_id');
    }

    /**
     * Get all of the access tokens for the user.
     *
     * @return \Illuminate\Database\Eloquent\Relations\HasMany
     */
    public function tokens()
    {
        return $this->hasMany(\DaniloPolani\FusionAuthJwt\Token::class, 'user_id')->orderBy('created_at', 'desc');
    }

    /**
     * Get the current access token being used by the user.
     *
     * @return Token|null
     */
    public function token()
    {
        return $this->accessToken;
    }

    /**
     * Determine if the current API token has a given scope.
     *
     * @param  string  $scope
     * @return bool
     */
    public function tokenCan($scope)
    {
        return $this->accessToken ? $this->accessToken->can($scope) : false;
    }

    /**
     * Create a new personal access token for the user.
     *
     * @param  string  $name
     * @param  array  $scopes
     * @return PersonalAccessTokenResult
     */
    public function createToken($name, array $scopes = [])
    {
        $supportedAlgs = \Config::get('fusionauth.supported_algs');
        /**
         * @var FusionAuthClient $FAClilent
         */
        $FAClilent = \App::make(\FusionAuth\FusionAuthClient::class);
        $token = $FAClilent->vendJWT([
            // 1 year
            'timeToLiveInSeconds' => 31536000,
            'claims' => [
                'sub' => $this->uuid,
                'scopes' => $scopes
            ]
        ]);
        if (!empty($token)) {
            $token = $token->successResponse->token;
            // Read Token attributes and get the jit
            $FAValidatedToken = $FAClilent->validateJWT($token);
            if ($FAValidatedToken->wasSuccessful()) {
                $id = $FAValidatedToken->successResponse->jwt->jti;
            } else {
                throw new InvalidTokenException('Invalid Token was generated', 500);
            }
            // Create token with attributes
            $tokenModel = \DaniloPolani\FusionAuthJwt\Token::create(
                [
                    'id' => $id,
                    'user_id' => $this->id,
                    'client_id' => Client::where('personal_access_client','=',1)->firstOrFail()->id, // Always use this for now as our client is external
                    'name' => $name,
                    'scopes' => $scopes,
                    'revoked' => false,
                    'created_at' => time(),
                    'updated_at' => time(),
                    'expires_at' => Carbon::now()->addSeconds(31536000)
                ]
            );
            return new \DaniloPolani\FusionAuthJwt\PersonalAccessTokenResult($token,
                $tokenModel
            );
        }
    }

    /**
     * Set the current access token for the user.
     *
     * @param  Token $accessToken
     * @return $this
     */
    public function withAccessToken($accessToken)
    {
        $this->accessToken = $accessToken;

        return $this;
    }
}
