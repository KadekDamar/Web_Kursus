<?php

namespace Database\Seeders;

use App\Models\User;
// use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\Hash;

class DatabaseSeeder extends Seeder
{
    /**
     * Seed the application's database.
     */
    public function run(): void
    {
        User::create([
            'name' => 'Admin',
            'email' => 'admin@admin.com',
            'password' => Hash::make('admin123'),
            'role' => 'admin',
            'email_verified_at' => now()
        ]);
        User::create([
            'name' => 'User',
            'email' => 'user@user.com',
            'password' => Hash::make('user123'),
            'role' => 'user',
            'email_verified_at' => now()
        ]);

        $this->call(JadwalSeeder::class);
        $this->call(BeritaSeeder::class);
    }
}
