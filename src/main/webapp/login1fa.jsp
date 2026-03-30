<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Inicio de sesión (1FA)</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="<%= request.getContextPath() %>/css/estilos.css">
</head>
<body>

<div class="login-container">
    <div class="login-card">
        <h2>Inicio de Sesión</h2>
        <% if (request.getAttribute("error") != null) { %>
            <p class="error-msg"><%= request.getAttribute("error") %></p>
        <% } %>

        <form action="LoginServlet" method="post">
            <label>DNI:</label>
            <input type="text" name="dni"
                   value="<%= request.getAttribute("dniRecordado") != null ? request.getAttribute("dniRecordado") : "" %>"
                   required>

            <label>Contraseña:</label>
            <input type="password" name="contrasena" required>

            <p><a href="recuperarContrasena.jsp">¿Olvidaste tu contraseña?</a></p>
            <input type="hidden" name="modoLogin" value="1FA">

            <button type="submit" class="btn-primary">Iniciar sesión</button>

            <input type="hidden" id="latitud" name="latitud">
            <input type="hidden" id="longitud" name="longitud">
        </form>
    </div>

    <div class="login-card">
        <h3>Iniciar sesión con Authenticator (TOTP)</h3>
        <form action="LoginTOTPServlet" method="post">
            <label>DNI:</label>
            <input type="text" name="dni" required>
            <label>Código TOTP:</label>
            <input type="text" name="totp" required>
            <input type="hidden" name="modoLogin" value="1FA">
            <button type="submit" class="btn-primary">Iniciar sesión con Authenticator</button>
        </form>
    </div>

    <div class="login-card">
        <h3>Iniciar sesión con biometría</h3>
        <label>DNI:</label>
        <input type="text" id="dniBiometria" required>
        <button type="button" id="btnBiometria" class="btn-primary">Iniciar sesión con biometría</button>
    </div>

    <div class="login-card">
        <h3>Iniciar sesión con dispositivo FIDO2</h3>
        <label>DNI:</label>
        <input type="text" id="dniFIDO2" required>
        <button type="button" id="btnFIDO2" class="btn-primary">Iniciar sesión con FIDO2</button>
    </div>

    <div class="login-card">
        <h3>Iniciar sesión con Passkey</h3>
        <label>DNI:</label>
        <input type="text" id="dniPasskey" required>
        <button type="button" id="btnPasskey" class="btn-primary">Iniciar sesión con Passkey</button>
    </div>

    <p class="register-text">
        ¿No tienes cuenta? <a href="registro.jsp">Regístrate aquí</a>
    </p>

    <div style="margin-top:15px; text-align:center;">
        <a href="index.jsp" class="btn-secondary" style="text-decoration:none;">Volver al inicio</a>
    </div>
</div>

<script>
    const contextPath = '<%= request.getContextPath() %>';
</script>

<script src="<%= request.getContextPath() %>/js/login1fa.js"></script>

</body>
</html>