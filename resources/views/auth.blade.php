<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login|Register Kursus</title>
    <link rel="shortcut icon" href="{{asset('favicon.png')}}" type="image/x-icon">
    <link rel="stylesheet" href="{{asset('assets/css/style-auth.css')}}">
    <link rel="stylesheet" href="https://unicons.iconscout.com/release/v4.0.0/css/line.css">
</head>
<body>
    @include('fragment.alert')
    <a href="/" class="submit-btn back">Back</a>
    <div class="form-container sign-in-form">
        <div class="form-box sign-in-box">
            <h2>Login</h2>
            <form action="{{route('login')}}" method="POST">
                @csrf
                <div class="field">
                    <i class="uil uil-at"></i>
                    <input type="email" placeholder="Email ID" name="email" value="{{old('email')}}" required>
                </div>
                <div class="field">
                    <i class="uil uil-lock-alt"></i>
                    <input type="password" class="password-input" placeholder="Password" name="password" required>
                    <div class="eye-btn"><i class="uil uil-eye-slash"></i></div>
                </div>
                <div class="forget-link">
                    <a href="">Forget password?</a>
                </div>
                <input type="submit" class="submit-btn" value="Login">
            </form>
            <div class="login-options">
                <p class="text">Or, login with...</p>
                <div class="other-logins">
                    <a href=""><img src="{{asset('assets/images/google-logo.png')}}" alt=""></a>
                    <a href=""><img src="{{asset('assets/images/facebook-logo.png')}}" alt=""></a>
                    <a href=""><img src="{{asset('assets/images/apple-logo.png')}}" alt=""></a>
                </div>
            </div>
        </div>
        <div class="imgBox sign-in-imgBox">
            <div class="sliding-link">
                <p>Don't have an account?</p>
                <span class="sign-up-btn">Sign up</span>
            </div>
            <img src="signup-img.png" alt="">
        </div>
    </div>

    <div class="form-container sign-up-form">
        <div class="imgBox sign-up-imgBox">
            <div class="sliding-link">
                <p>Already a member?</p>
                <span class="sign-in-btn">Sign in</span>
            </div>
            <img src="signin-img.jpg" alt="">
        </div>
        <div class="form-box sign-up-box">
            <h2>Sign up</h2>
            <div class="login-options">
                <div class="other-logins">
                    <a href=""><img src="{{asset('assets/images/google-logo.png')}}" alt=""></a>
                    <a href=""><img src="{{asset('assets/images/facebook-logo.png')}}" alt=""></a>
                    <a href=""><img src="{{asset('assets/images/apple-logo.png')}}" alt=""></a>
                </div>
                <p class="text">Or, sign up with email...</p>
            </div>
            <form action="{{route('register')}}" method="POST">
                @csrf
                <div class="field">
                    <i class="uil uil-at"></i>
                    <input type="email" placeholder="Email ID" name="email" required>
                </div>
                <div class="field">
                    <i class="uil uil-user"></i>
                    <input type="text" placeholder="Full name" name="name" required>
                </div>
                <div class="field">
                    <i class="uil uil-lock-alt"></i>
                    <input type="password" placeholder="Password" name="password" required>
                </div>
                <input type="submit" class="submit-btn" value="Sign up">
            </form>
        </div>
    </div>


    <script>
        const textInputs = document.querySelectorAll("input");

        textInputs.forEach(textInput => {
            textInput.addEventListener("focus",() => {
                let parent = textInput.parentNode;
                parent.classList.add("active");
            });

            textInput.addEventListener("blur",() => {
                let parent = textInput.parentNode;
                parent.classList.remove("active");
            });

        });

        const passwordInput = document.querySelector(".password-input");
        const eyeBtn = document.querySelector(".eye-btn");

        eyeBtn.addEventListener("click",() => {
            if(passwordInput.type === "password"){
                passwordInput.type = "text";
                eyeBtn.innerHTML = "<i class='uil uil-eye'></i>";
            }else{
                passwordInput.type = "password";
                eyeBtn.innerHTML = "<i class='uil uil-eye-slash'></i>";
            }
        });

        const signUpBtn = document.querySelector(".sign-up-btn");
        const signInBtn = document.querySelector(".sign-in-btn");
        const signUpForm = document.querySelector(".sign-up-form");
        const signInForm = document.querySelector(".sign-in-form");

        signUpBtn.addEventListener("click",() => {
            signInForm.classList.add("hide");
            signUpForm.classList.add("show");
            signInForm.classList.remove("show");
        });

        signInBtn.addEventListener("click",() => {
            signInForm.classList.remove("hide");
            signUpForm.classList.remove("show");
            signInForm.classList.add("show");
        });
    </script>
</body>
</html>