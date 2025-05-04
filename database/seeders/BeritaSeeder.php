<?php

namespace Database\Seeders;

use App\Models\Berita;
use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;

class BeritaSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        Berita::create([
            'konten' => "Kami dengan bangga mengumumkan penambahan modul baru dalam kursus Menjahit dan Membuat Kue yang akan dimulai bulan depan. Modul ini dirancang untuk meningkatkan keterampilan praktis dan teoritis Anda, dengan fokus pada teknik canggih dan desain terkini. Pengenalan teknologi terbaru dalam kursus Menjahit memberikan kesempatan untuk belajar menggunakan mesin jahit digital yang lebih efisien. Untuk kursus Membuat Kue, kami telah memperbarui resep dan teknik dengan mengikutsertakan metode-metode modern yang lebih berkelanjutan dan efektif.
                            Jangan lewatkan sesi webinar yang akan kami adakan pada akhir bulan, dimana instruktur kami akan mendemonstrasikan penggunaan peralatan modern di kedua kursus dan menjawab pertanyaan dari peserta. Daftarkan diri Anda sekarang melalui dashboard atau hubungi admin kursus untuk informasi lebih lanjut!"
        ]);
    }
}
