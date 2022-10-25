<?php

namespace DaniloPolani\FusionAuthJwt;

use DaniloPolani\FusionAuthJwt\Exceptions\InvalidTokenAlgorithmException;
use DaniloPolani\FusionAuthJwt\Exceptions\InvalidTokenException;
use Firebase\JWT\JWT;
use FusionAuth\FusionAuthClient;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Http;

class FusionAuthJwt
{
    /**
     * Default length of cache persistence. Defaults to 10 minutes.
     *
     * @see https://www.php-fig.org/psr/psr-16/#12-definitions
     */
    public const JWKS_CACHE_TTL = 600;

    public const ALGO_RS256 = 'RS256';

    public const ALGO_HS256 = 'HS256';

    private $fusionAuthClient = false;

    /**
     * Decode a JWT.
     *
     * @param string $jwt
     * @return array
     * @throws InvalidTokenAlgorithmException             Provided algorithm is not supported
     * @throws InvalidTokenException                      Decoded JWT iss or aud are invalid
     *
     * @throws \InvalidArgumentException                  Provided JWT was empty
     * @throws \UnexpectedValueException                  Provided JWT was invalid
     * @throws \Firebase\JWT\SignatureInvalidException    Provided JWT was invalid because the signature verification failed
     * @throws \Firebase\JWT\BeforeValidException         Provided JWT is trying to be used before it's eligible as defined by 'nbf'
     * @throws \Firebase\JWT\BeforeValidException         Provided JWT is trying to be used before it's been created as defined by 'iat'
     * @throws \Firebase\JWT\ExpiredException             Provided JWT has since expired, as defined by the 'exp' claim
     *
     */
    public static function decode(string $jwt): array
    {
        $supportedAlgs = Config::get('fusionauth.supported_algs');

        if (!in_array($supportedAlgs[0] ?? null, [self::ALGO_RS256, self::ALGO_HS256])) {
            throw new InvalidTokenAlgorithmException('Unsupported token signing algorithm configured. Must be either RS256 or HS256.');
        }

        $client = \App::make(\FusionAuth\FusionAuthClient::class);
        if (!$client) {
            return false;
        } else {
            /**
             * @var  FusionAuthClient $client
             */
            $validatedToken = $client->validateJWT($jwt);
            if ($validatedToken->wasSuccessful()) {
                $data = $client->retrieveUserUsingJWT($jwt);
                if ($data->wasSuccessful()) {
                    $data = $data->successResponse->user;
                } else {
                    // try to get the user, from the token
                    $token = Token::firstWhere([
                        'id' => $validatedToken->successResponse->jwt->jti,
                        'revoked' => false
                    ]);

                    if ($token) {
                        $data = $token->user->toArray();
                    } else {
                        throw new InvalidTokenException('Token can not be authenticated against server.');
                    }
                }
            } else {
                //should we try to auto-renew the token here?, or we let the front end handle it ?
                throw new InvalidTokenException('Token is invalid', 500);
            }

        }

        return ['user' => (array)$data, 'token' => $validatedToken->successResponse->jwt];
    }

    /**
     * Validate a token by its aud and iss.
     *
     * @param object $token
     * @return void
     * @throws InvalidTokenException
     *
     */
    public static function validate(object $token): void
    {
        if (!in_array($token->iss, Config::get('fusionauth.issuers'))) {
            throw new InvalidTokenException('Issuer "' . $token->iss . '" is not authorized.');
        }

        $possibleAudiences = [
            // Fallback to client_id to avoid "null $token->aud" matching "null fusionauth.audience"
            Config::get('fusionauth.audience', Config::get('fusionauth.client_id')),
            Config::get('fusionauth.client_id'),
        ];

        // Validate aud against the audience and client id (may be a token from client_credentials)
        if (!in_array($token->aud, $possibleAudiences)) {
            throw new InvalidTokenException('Audience "' . $token->aud . '" is not authorized.');
        }
    }


}
