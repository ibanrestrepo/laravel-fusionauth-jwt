<?php

namespace DaniloPolani\FusionAuthJwt;

use App\Http\Resources\CurrentUserResource;
use \Illuminate\Http\Request;
use Illuminate\Auth\RequestGuard;


class DefaultMixedGuard extends RequestGuard {

    public function login($user = false) {
        if ($user) {
            return new CurrentUserResource($user);
        }
    }

    public function logout() {
        /**
         * @var FusionAuthJwtUserProvider
         */
        $request = Request::capture();
        $refreshTokenHeader = $request->header('x-refresh-token') ?? false;
        $this->provider->closeSessionWithMessage($refreshTokenHeader, false);
    }
}
