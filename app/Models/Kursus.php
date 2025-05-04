<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Kursus extends Model
{
    use HasFactory;

    protected $table = 'kursus';

    protected $fillable = [
        'name',
        'email',
        'phone',
        'alamat',
        'alasan',
        'kursus',
        'status'
    ];
}
