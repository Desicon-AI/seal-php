<?php

namespace Desicon\Seal\Laravel\Commands;

use Illuminate\Console\Command;
use Desicon\Seal\Client;

class HeartbeatCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'seal:heartbeat';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Send a continuous background heartbeat to the Seal/Seal Engine (Server Cron)';

    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle()
    {
        $apiKey = config('seal.api_key', env('SEAL_API_KEY'));
        
        if (!$apiKey) {
            $this->error('SEAL_API_KEY is not set in your .env file.');
            return 1;
        }

        // Initialize Client so that static variables are populated
        Client::init([
            'apiKey' => $apiKey,
                'signingSecret' => config('seal.signing_secret', env('SEAL_SIGNING_SECRET')),
                'endpoint' => config('seal.endpoint', 'https://sealengine.desicon.ai/api/v1/ingest'),
            'appName' => config('app.name', 'laravel-app'),
            'environment' => config('app.env', 'production'),
        ]);

        // Dispatch the heartbeat explicitly as 'server_cron'
        if (!Client::sendCronHeartbeat()) {
            $this->error('Seal heartbeat delivery was not acknowledged.');
            return 1;
        }

        $this->info('Seal Heartbeat sent successfully.');
        return 0;
    }
}
