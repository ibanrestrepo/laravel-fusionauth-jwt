<?php

namespace DaniloPolani\FusionAuthJwt;

use App\User;
use Carbon\Carbon;
use Exception;
use FusionAuth\FusionAuthClient;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Validation\ValidationException;
use Laravel\Passport\TransientToken;
use Symfony\Component\HttpFoundation\Session\Session;


class FusionAuthJwtUserProvider implements UserProvider
{

    public function username()
    {
        return 'username';
    }

    /**
     * Resets session if Token or client can't be started
     * @return void
     */
    public function closeSessionWithMessage($refreshToken = false, $messageCode = 'auth.error')
    {
        /**
         * @var FusionAuthClient $fa
         */
        $fa = \App::make(\FusionAuth\FusionAuthClient::class);
        $res = $fa->logout(true, $refreshToken ?? false);
        \session()->invalidate();
        \session()->regenerateToken();

        if ($messageCode) {
            throw ValidationException::withMessages([
                $this->username() => [trans($messageCode)],
            ]);
        }
    }

    /**
     * {@inheritDoc}
     */
    public function retrieveByCredentials(array $credentials)
    {
        $request = Request::capture();
        $jwt = $credentials['jwt'] ?? null;

        if ($jwt == 'null' || empty($jwt)) {
            return null;
        }

        try {
            $decodedJwt = FusionAuthJwt::decode($jwt);
        } catch (Exception $e) {
            $this->closeSessionWithMessage($credentials['refreshToken'], 'auth.failed');
        }

        if (empty($decodedJwt)) {
            $this->closeSessionWithMessage($credentials['refreshToken'], 'auth.authentication_header_missing');
        }


        $user = new FusionAuthJwtUser($decodedJwt['user']);
        $userModel = $user->getLocalUserInfo();

        if ($userModel instanceof User) {
            /**
             * @var User $user
             */
            // Create token OBJECT w/o saving it
            $token = (array)$decodedJwt['token'];
            if (!empty($token) && isset($token['scopes'])) {
                // When using custom ISSUED tokens, they do have scopes
                $userModel->withAccessToken(Token::find($token['jti']) ?? null);
                //
            } else {
                $userModel->withAccessToken(new \Laravel\Passport\TransientToken());
            }

            if ($userModel->token() instanceof TransientToken) {
                if ($userModel->isMerchant()) {
                    $url_array = parse_url($_SERVER['HTTP_REFERER'] ?? '');
                    $url_array['host'] = explode('.', $url_array['host']);
                    $clientSubdomain = $url_array['host'][0] ?? 'invalid';

                    if ($clientSubdomain) {
                        if (strtolower($clientSubdomain) !== strtolower($userModel->merchant->subdomain)) {
                            $this->closeSessionWithMessage($credentials['refreshToken'], 'auth.invalid_subdomain');
                        }
                    }
                }
            }

            if ($userModel->isMerchant()) {
                if ($userModel->merchant->isClosed()) {
                    $this->closeSessionWithMessage($credentials['refreshToken'], 'auth.closed');
                }

                if (app()->environment() === 'local' || app()->environment() === 'testing') {
                    $ip_address = $request->ip();
                } else {
                    $ip_address = $request->getForwardedIp() ?? $request->getClientIp();
                }
                if (!$userModel->merchant->validateIpAddress($ip_address)) {
                    $this->closeSessionWithMessage($credentials['refreshToken'], 'auth.ip_blocked');
                }
            }

            $userModel->save();
            return $userModel;
        } else {
            $this->closeSessionWithMessage($credentials['refreshToken'], 'auth.failed');
        }

    }

    /**
     * {@inheritDoc}
     */
    public function retrieveById($identifier)
    {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    public function retrieveByToken($identifier, $token)
    {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    public function updateRememberToken(Authenticatable $user, $token)
    {
        //
    }

    /**
     * {@inheritDoc}
     */
    public function validateCredentials(Authenticatable $user, array $credentials)
    {
        return false;
    }
}
