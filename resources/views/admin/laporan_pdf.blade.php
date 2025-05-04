<!DOCTYPE html>
<html>
<head>
    <title>Laporan Pengajuan</title>
    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            font-family: 'Arial', sans-serif;
            margin: 20px;
        }
        .table th, .table td {
            border: 1px solid #dee2e6;
            padding: 8px;
            vertical-align: top;
        }
        .table thead th {
            border-bottom: 2px solid #dee2e6;
        }
        .table tfoot th {
            border-top: 2px solid #dee2e6;
        }
        h1, h2 {
            text-align: center;
            margin-bottom: 20px;
        }
        .user-info {
            margin-bottom: 20px;
        }
        .table td.alamat, .table td.alasan {
            word-wrap: break-word;
            white-space: pre-wrap; 
        }
        .table th.name, .table td.name {
            width: 15%;
        }
        .table th.email, .table td.email {
            width: 15%;
        }
        .table th.nohp, .table td.nohp {
            width: 10%;
        }
        .table th.alamat, .table td.alamat {
            width: 20%;
        }
        .table th.alasan, .table td.alasan {
            width: 25%;
        }
        .table th.kursus, .table td.kursus {
            width: 10%;
        }
        .table th.status, .table td.status {
            width: 10%;
        }
    </style>
</head>
<body>
    <h1>Laporan Pengajuan Pengguna</h1>
    <div class="user-info">
        <p>Laporan pengguna yang mengajukan pengajuan untuk mengikuti kursus sebagai berikut:</p>
    </div>

    <table class="table table-bordered">
        <thead>
            <tr>
                <th class="name">Name</th>
                <th class="email">Email</th>
                <th class="nohp">Phone</th>
                <th class="alamat">Alamat</th>
                <th class="alasan">Alasan</th>
                <th class="kursus">Kursus</th>
                <th class="status">Status</th>
            </tr>
        </thead>
        <tbody>
            @foreach ($data as $pengguna)
                <tr>
                    <td class="name">{{ $pengguna['name'] }}</td>
                    <td class="email">{{ $pengguna['email'] }}</td>
                    <td class="nohp">{{ $pengguna['phone'] }}</td>
                    <td class="alamat">{{ $pengguna['alamat'] }}</td>
                    <td class="alasan">{{ $pengguna['alasan'] }}</td>
                    <td class="kursus">{{ $pengguna['kursus'] }}</td>
                    <td class="status">{{ $pengguna['status'] }}</td>
                </tr>
            @endforeach
        </tbody>
    </table>
</body>
</html>
