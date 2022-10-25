<?php

namespace DaniloPolani\FusionAuthJwt;

use DaniloPolani\FusionAuthJwt\Http\Middleware\CheckRole;
use DaniloPolani\FusionAuthJwt\FusionAuthequestGuard;
use Illuminate\Auth\RequestGuard;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider;
use \DaniloPolani\FusionAuthJwt\DefaultMixedGuard;

class FusionAuthJwtServiceProvider extends ServiceProvider
{
    public function register()
    {
        // Automatically apply the package configuration
        $this->mergeConfigFrom(__DIR__.'/../config/fusionauth.php', 'fusionauth');
    }

    public function boot()
    {
        Auth::provider(
            'fusionauth',
            fn (Application $app) => $app->make(FusionAuthJwtUserProvider::class)
        );

        Auth::extend(
            'fusionauth',
            fn (Application $app, string $name, array $config) => new DefaultMixedGuard(
                fn (Request $request, FusionAuthJwtUserProvider $provider) => $provider->retrieveByCredentials([
                    'jwt' => $request->bearerToken() ?? $request->input('token'),
                    'refreshToken' => $request->input('refreshToken')
                ]),
                $app['request'],
                $app['auth']->createUserProvider($config['provider'])
            )
        );

        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../config/fusionauth.php' => config_path('fusionauth.php'),
            ], 'fusionauth-jwt-config');
        }
    }

}
