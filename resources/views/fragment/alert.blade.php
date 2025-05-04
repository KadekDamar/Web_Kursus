<link rel="stylesheet" href="{{ asset('assets/css/alert.css') }}">
<div id="message-container"></div>
<script src="{{ asset('assets/js/alert.js') }}"></script>

@if(session('success'))
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            showMessage('{{ session('success') }}');
        });
    </script>
@endif

@if(session('error'))
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            showError('{{ session('error') }}');
        });
    </script>
@endif

@if($errors->any())
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            let errorMessages = '';
            @foreach ($errors->all() as $error)
                errorMessages += '{{ $error }}\n';
            @endforeach
            showError(errorMessages);
        });
    </script>
@endif