<?php

namespace Desicon\Seal\Laravel;

use Illuminate\Support\ServiceProvider;
use Desicon\Seal\Client;
use Desicon\Seal\Laravel\Commands\HeartbeatCommand;

class SealServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     *
     * @return void
     */
    public function register()
    {
        // Register the Artisan Command
        $this->commands([
            HeartbeatCommand::class,
        ]);
    }

    /**
     * Bootstrap any application services.
     *
     * @return void
     */
    public function boot()
    {
        $apiKey = config('seal.api_key', env('SEAL_API_KEY'));

        if ($apiKey) {
            Client::init([
                'apiKey' => $apiKey,
                'appName' => config('app.name', 'laravel-app'),
                'environment' => config('app.env', 'production'),
                // Developers can publish a seal.php config to customize the WAF
                'waf' => config('seal.waf', [])
            ]);
        }
    }
}
