<?php

use App\Http\Controllers\AdminController;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\UserController;
use Illuminate\Support\Facades\Route;


Route::get('/', function () {
    return view('welcome');
});
Route::middleware(['guest'])->group(function(){
    Route::get('auth',[AuthController::class,'auth'])->name('auth');
    Route::post('register',[AuthController::class,'register'])->name('register');
    Route::post('login',[AuthController::class,'login'])->name('login');
});

Route::get('admin',[AdminController::class,'index'])->name('admin')->middleware('role:admin');
Route::get('user',[UserController::class,'index'])->name('user')->middleware('role:user');

Route::middleware(['auth'])->group(function(){
    // User Fitur
    Route::get('sew',[UserController::class,'sew'])->name('sew');
    Route::get('cake',[UserController::class,'cake'])->name('cake');

    Route::post('create',[UserController::class,'create'])->name('create');

    Route::get('jadwal',[UserController::class,'jadwal'])->name('jadwal');
    Route::get('laporan',[UserController::class,'laporan'])->name('laporan');

    Route::post('generate-laporan',[UserController::class,'generateLaporanPdf'])->name('generateLaporanPdf');

    // Admin Fitur
    Route::get('control-sew', [AdminController::class, 'controlSew'])->name('sewadmin');
    Route::get('control-cake', [AdminController::class, 'controlCake'])->name('cakeadmin');
    Route::get('laporan-admin', [AdminController::class, 'laporanAdmin'])->name('laporanadmin')->middleware('auth');
    Route::get('control-user', [AdminController::class, 'controlUser'])->name('users');
    Route::get('jadwal-sew', [AdminController::class, 'jadwalSew'])->name('jadwalsew');
    Route::get('jadwal-cake', [AdminController::class, 'jadwalCake'])->name('jadwalcake');
    Route::post('admin/update-berita', [AdminController::class, 'updateBerita'])->name('admin.updateBerita')->middleware('auth');
    Route::post('admin/approve/{id}', [AdminController::class, 'approve'])->name('admin.approve');
    Route::post('admin/reject/{id}', [AdminController::class, 'reject'])->name('admin.reject');
    Route::post('admin/jadwal', [AdminController::class, 'storeJadwal'])->name('storeJadwal');
    Route::post('admin/jadwal/{id}', [AdminController::class, 'updatejadwal'])->name('updatejadwal');
    Route::delete('admin/jadwal/{id}', [AdminController::class, 'destroyJadwal'])->name('destroyJadwal');
    Route::get('admin/jadwal/{id}/edit', [AdminController::class, 'edit']);
    Route::post('generate-laporan-admin', [AdminController::class, 'generateLaporanAdminPdf'])->name('generateLaporanAdminPdf')->middleware('auth');
});

Route::post('logout',[AuthController::class,'logout'])->name('logout');

Route::get('verify/{id}/{hash}',[AuthController::class, 'verify'])->name('verification.verify');