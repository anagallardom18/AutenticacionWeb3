package autenticacion;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import jakarta.servlet.annotation.WebServlet;
import java.io.IOException;

/**
 * Servlet encargado de validar los códigos OTP (One-Time Password) enviados por email.
 * Maneja dos flujos distintos: Login con Doble Factor y Recuperación de Contraseña.
 */
@WebServlet("/OTPServlet")
public class OTPServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        // 1. OBTENCIÓN DE SESIÓN: Intentamos recuperar la sesión existente. 
        // Si no existe (false), el usuario ha tardado demasiado o es un acceso ilegal.
        HttpSession sesion = request.getSession(false); 
        if (sesion == null) {
            response.sendRedirect("login.jsp");
            return;
        }

        // Recuperamos el código que el usuario escribió en el formulario
        String codigoIntroducido = request.getParameter("otp");
        
        // Esta bandera nos dice si estamos en "Modo Recuperación" o "Modo Login"
        Boolean esRecuperacion = (Boolean) sesion.getAttribute("recuperacion");

        // --- FLUJO A: RECUPERACIÓN DE CONTRASEÑA ---
        if (esRecuperacion != null && esRecuperacion) {
            // Sacamos los datos que guardó previamente el servlet de recuperación
            String otpCorrecto = (String) sesion.getAttribute("otpRecuperacion");
            String emailRecuperacion = (String) sesion.getAttribute("emailRecuperacion");

            // Si faltan datos en sesión, algo falló en el paso anterior
            if (otpCorrecto == null || emailRecuperacion == null) {
                response.sendRedirect("recuperarContrasena.jsp");
                return;
            }

            // Verificamos si el código introducido coincide con el enviado al email
            if (codigoIntroducido != null && codigoIntroducido.equals(otpCorrecto)) {
                // ÉXITO: Creamos un "token de permiso" en sesión para que el siguiente 
                // servlet sepa que este usuario realmente validó su identidad.
                sesion.setAttribute("permisoCambio", true); 
                
                // Limpieza: El código ya no es necesario una vez usado
                sesion.removeAttribute("otpRecuperacion");
                response.sendRedirect("cambiarContrasena.jsp");
            } else {
                // ERROR: Volvemos a mostrar el formulario con un mensaje de error
                request.setAttribute("error", "Código de recuperación incorrecto.");
                request.getRequestDispatcher("verificaOTP.jsp").forward(request, response);
            }

        // --- FLUJO B: 2FA NORMAL (LOGIN) ---
        } else {
            // Sacamos los datos que guardó el LoginServlet
            String otpCorrecto = (String) sesion.getAttribute("otp");
            String usuarioTemp = (String) sesion.getAttribute("usuarioTemp");

            if (otpCorrecto == null || usuarioTemp == null) {
                response.sendRedirect("login.jsp");
                return;
            }

            // Validación del código para entrar en la aplicación
            if (codigoIntroducido != null && codigoIntroducido.equals(otpCorrecto)) {
                // ÉXITO: Promocionamos al usuario de "Temporal" a "Oficial"
                sesion.setAttribute("usuario", usuarioTemp);

                // SEGURIDAD: Borramos el OTP y el usuario temporal para evitar reutilización
                sesion.removeAttribute("otp");
                sesion.removeAttribute("usuarioTemp");

                response.sendRedirect("bienvenido.jsp");
            } else {
                // ERROR: El código no coincide
                request.setAttribute("error", "Código incorrecto. Inténtelo de nuevo.");
                request.getRequestDispatcher("verificaOTP.jsp").forward(request, response);
            }
        }
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // Bloqueamos el acceso por URL (GET) redirigiendo al login
        response.sendRedirect("login.jsp");
    }
}