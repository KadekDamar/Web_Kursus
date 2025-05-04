<!DOCTYPE html>
<html>
<head>
    <title>Laporan Kursus</title>
    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            font-family: 'Arial', sans-serif;
        }
        .table th, .table td {
            border: 1px solid #dee2e6;
            padding: 8px;
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
    </style>
</head>
<body>
    <h1>Laporan Kursus {{ $user->name }}</h1>
    <div class="user-info">
        <p><strong>ID Kursus:</strong> {{ $idKursus }}</p>
        <p><strong>No Pelajar:</strong> {{ $noPelajar }}</p>
    </div>

    <h2>Laporan Kursus</h2>
    <table class="table table-bordered">
        <thead>
            <tr>
                <th>Name</th>
                <th>Email</th>
                <th>Phone</th>
                <th>Course</th>
                <th>Start Date</th>
            </tr>
        </thead>
        <tbody>
            @foreach ($laporan as $data)
                <tr>
                    <td>{{ $data['name'] }}</td>
                    <td>{{ $data['email'] }}</td>
                    <td>{{ $data['phone'] }}</td>
                    <td>{{ $data['kursus'] }}</td>
                    <td>{{ $data['start'] }}</td>
                </tr>
            @endforeach
        </tbody>
    </table>

    @if ($isJadwal->isNotEmpty())
        <h2>Jadwal Kursus</h2>
        <table class="table table-bordered">
            <thead>
                <tr>
                    <th>Kursus</th>
                    <th>Hari</th>
                    <th>Tanggal</th>
                    <th>Waktu</th>
                    <th>Tempat</th>
                    <th>Instruktur</th>
                </tr>
            </thead>
            <tbody>
                @foreach ($isJadwal as $jadwal)
                    <tr>
                        <td>{{ $jadwal->kursus }}</td>
                        <td>{{ $jadwal->hari }}</td>
                        <td>{{ $jadwal->tanggal }}</td>
                        <td>{{ $jadwal->waktu }}</td>
                        <td>{{ $jadwal->tempat }}</td>
                        <td>{{ $jadwal->instruktur }}</td>
                    </tr>
                @endforeach
            </tbody>
        </table>
    @endif
</body>
</html>
