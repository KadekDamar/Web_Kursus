<?php

namespace App\Http\Controllers;

use App\Models\Berita;
use App\Models\Jadwal;
use App\Models\Kursus;
use App\Models\Pemberitahuan;
use App\Models\User;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Barryvdh\DomPDF\Facade\Pdf;

class AdminController extends Controller
{
    function index()
    {

        $berita = Berita::first();

        $countAdmin = User::where('role', 'admin')->count();
        $countPengguna = User::where('role', 'user')->count();

        return view('admin.index', ['countAdmin' => $countAdmin, 'countPengguna' => $countPengguna, 'berita' => $berita]);
    }

    function controlSew()
    {
        $dataSew = Kursus::where('kursus', 'sew')->get();
        return view('admin.sew', ['dataSew' => $dataSew]);
    }
    function controlCake()
    {
        $dataCake = Kursus::where('kursus', 'cake')->get();
        return view('admin.cake', ['dataCake' => $dataCake]);
    }
    function controlUser()
    {
        $dataPengguna = User::where('role', 'user')->get();

        return view('admin.users', ['dataPengguna' => $dataPengguna]);
    }
    function jadwalSew()
    {
        $jadwalSew = Jadwal::where('kursus', 'sew')->get();
        return view('admin.jadwal_sew', ['jadwalSew' => $jadwalSew]);
    }
    function jadwalCake()
    {
        $jadwalCake = Jadwal::where('kursus', 'cake')->get();
        return view('admin.jadwal_cake', ['jadwalCake' => $jadwalCake]);
    }

    public function updateBerita(Request $request)
    {
        $request->validate([
            'konten' => 'required|string',
        ]);

        $berita = Berita::first();
        $berita->konten = $request->input('konten');
        $berita->save();

        return redirect()->route('admin')->with('success', 'Berita berhasil diperbarui.');
    }

    public function approve($id)
    {
        $sew = Kursus::find($id);

        if ($sew) {
            $sew->status = 'Disetujui';
            $sew->save();
        }

        $currentWaktu = Carbon::now()->format('F j, Y');

        Pemberitahuan::create([
            'email' => $sew->email,
            'waktu' => $currentWaktu,
            'pesan' => "Selamat! Admin telah Menyetujui anda untuk mengikuti kursus $sew->kursus! Periksa Jadwal anda saat ini. See You!",
            'type' => "info"
        ]);

        return redirect()->back()->with('success', 'Pengajuan berhasil disetujui.');
    }

    public function reject($id)
    {
        $sew = Kursus::find($id);

        if ($sew) {
            $sew->status = 'Ditolak';
            $sew->save();
        }

        $currentWaktu = Carbon::now()->format('F j, Y');

        Pemberitahuan::create([
            'email' => $sew->email,
            'waktu' => $currentWaktu,
            'pesan' => "Jangan Patah Semangat! Admin telah Menolak anda untuk mengikuti kursus $sew->kursus! GoodBye!",
            'type' => "info"
        ]);

        return redirect()->back()->with('success', 'Pengajuan berhasil ditolak.');
    }

    public function storeJadwal(Request $request)
    {
        // Validasi data
        $request->validate([
            'hari' => 'required|string|max:255',
            'tanggal' => 'required|date',
            'waktu_start' => 'required|date_format:H:i',
            'waktu_end' => 'required|date_format:H:i',
            'tempat' => 'required|string|max:255',
            'instruktur' => 'required|string|max:255',
            'kursus' => 'required|string|in:sew,cake',
        ]);

        // Buat jadwal baru
        Jadwal::create([
            'hari' => $request->input('hari'),
            'tanggal' => $request->input('tanggal'),
            'waktu' => $request->input('waktu_start') . ' - ' . $request->input('waktu_end'),
            'tempat' => $request->input('tempat'),
            'instruktur' => $request->input('instruktur'),
            'kursus' => $request->input('kursus'),
        ]);

        return redirect()->back()->with('success', 'Jadwal berhasil ditambahkan');
    }

    public function edit($id)
    {
        $jadwal = Jadwal::findOrFail($id);

        list($waktu_start, $waktu_end) = explode(' - ', $jadwal->waktu);

        return response()->json([
            'hari' => $jadwal->hari,
            'tanggal' => $jadwal->tanggal,
            'waktu_start' => $waktu_start,
            'waktu_end' => $waktu_end,
            'tempat' => $jadwal->tempat,
            'instruktur' => $jadwal->instruktur,
        ]);
    }

    public function updatejadwal(Request $request, $id)
    {
        // Validasi data
        $request->validate([
            'hari' => 'required|string|max:255',
            'tanggal' => 'required|date',
            'waktu_start' => 'required|date_format:H:i',
            'waktu_end' => 'required|date_format:H:i',
            'tempat' => 'required|string|max:255',
            'instruktur' => 'required|string|max:255',
            'kursus' => 'required|string|in:sew,cake',
        ]);

        // Temukan jadwal dan update
        $jadwal = Jadwal::findOrFail($id);
        $jadwal->hari = $request->input('hari');
        $jadwal->tanggal = $request->input('tanggal');
        $jadwal->waktu = $request->input('waktu_start') . ' - ' . $request->input('waktu_end');
        $jadwal->tempat = $request->input('tempat');
        $jadwal->instruktur = $request->input('instruktur');
        $jadwal->kursus = $request->input('kursus');
        $jadwal->save();

        return redirect()->back()->with('success', 'Jadwal berhasil diperbarui');
    }

    public function destroyJadwal(Request $request, $id)
    {
        $jadwal = Jadwal::findOrFail($id);
        $jadwal->delete();

        return redirect()->back()->with('success', 'Jadwal berhasil dihapus');
    }
    function laporanAdmin()
    {
        $data = Kursus::all();

        return view('admin.laporan', ['data' => $data]);
    }
    function generateLaporanAdminPdf()
    {
        $data = Kursus::all();

        $timestamp = now()->format('Ymd_His');
        $filename = 'laporan_pengajuan_' . $timestamp . '.pdf';

        $pdf = PDF::loadView('admin.laporan_pdf', ['data' => $data]);

        return $pdf->download($filename);
    }
}
