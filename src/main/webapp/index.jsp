<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Inicio</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="css/estilos.css">
</head>

<body>

<div class="login-container">

    <div class="login-card">
        <h2>Sistema de Autenticación</h2>

        <p style="text-align:center; margin-bottom:20px;">
            Selecciona el tipo de acceso
        </p>

        <!-- LOGIN SIN 2FA -->
        <a href="login1fa.jsp" style="text-decoration:none;">
            <button class="btn-primary">
                Login sencillo de un solo factor
            </button>
        </a>

        <br><br>

        <!-- LOGIN CON 2FA -->
        <a href="login.jsp" style="text-decoration:none;">
            <button class="btn-primary">
                Login con dos factores
            </button>
        </a>
		<br><br>
  <!-- ACCESO MEDIANTE QR -->
        <a href="QRMovilServlet" style="text-decoration:none;">
            <button class="btn-secondary">
                Acceder mediante QR
            </button>
        </a>

    </div>

</div>

</body>
</html>