<?php

namespace App\Http\Controllers;
use App\Models\User;
use Illuminate\Http\Request;
use App\Notifications\VerifyEmail;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Notification;

class AuthController extends Controller
{
    public function auth(){
        return view('auth');
    }

    public function register(Request $request){
        $request->validate([
            'name' => 'required',
            'email' => 'required|email|unique:users',
            'password' => 'required|min:6'
        ],[
            'name.required' => 'Nama Harus Diisi',
            'email.required' => 'Email Harus Diisi',
            'email.email' => 'Email Harus Valid',
            'email.unique' => 'Email Sudah Terdaftar',
            'password.required' => 'Password Harus Diisi',
            'password.min' => 'Password Minimal 6 Karakter'
        ]);
        try{
            $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => Hash::make($request->password)
            ]);

            $user->sendEmailVerificationNotification();

            return redirect()->route('auth')->with('success','Berhasil Mendaftar! Silahkan cek email untuk verifikasi akun anda!');
        }catch(\Exception $e){
            return redirect()->route('auth')->with('error','Gagal Mendaftar!'.$e);
        }
    }
    public function login(Request $request){
        $request->validate([
            'email' => 'required|email',
            'password' => 'required|min:6'
        ],[
            'email.required' => 'Email Harus Diisi',
            'email.email' => 'Email Harus Valid',
            'password.required' => 'Password Harus Diisi',
            'password.min' => 'Password Minimal 6 Karakter'
        ]);

        if (Auth::attempt($request->only('email','password'))){
            if (Auth::user()->email_verified_at){
                $request->session()->regenerate();
                if (Auth::user()->role ==='admin'){
                    return redirect()->route('admin')->with('success','Selamat Datang Admin!');
                }else{
                    return redirect()->route('user')->with('success','Anda Berhasil Masuk');
                }
            }else{
                Auth::logout();
                return back()->with('error','Harap Verifikasi Akun Anda!');
            }
        }
        return redirect()->route('auth')->with('error','Kombinasi Email dan Password Salah!');
    }

    public function verify($id, $hash)
    {
        $user = User::findOrFail($id);
    
        if (!hash_equals((string) $hash, sha1($user->getEmailForVerification()))) {
            return redirect()->route('auth')->with('error', 'Link Verifikasi Tidak Valid');
        }
    
        if ($user->hasVerifiedEmail()) {
            return redirect()->route('auth')->with('success', 'Akun Anda Sudah Terverifikasi');
        }
    
        if ($user->markEmailAsVerified()) {
            return redirect()->route('auth')->with('success', 'Akun Anda Berhasil Diverifikasi');
        }
    
        return redirect()->route('auth')->with('error', 'Gagal Verifikasi Email');
    }

    public function logout(Request $request){
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return redirect('/');
    }
    
}
