<%@ page contentType="text/html;charset=UTF-8" %>
<!DOCTYPE html>
<html>
<head>
    <title>QR de acceso</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <!-- Tu CSS -->
    <link rel="stylesheet" href="css/estilos.css">
</head>

<body>

<div class="login-container">

    <div class="login-card">

        <h2>Acceso mediante QR</h2>

        <p style="text-align:center; margin-bottom:15px;">
            Escanea este código con tu móvil para acceder
        </p>

        <!-- QR -->
        <img src="${qrImage}" class="qr-img" alt="QR de acceso"/>

        <!-- Botón volver -->
        <a href="index.jsp" style="text-decoration:none;">
            <button class="btn-primary">
                Volver al inicio
            </button>
        </a>

    </div>

</div>

</body>
</html>