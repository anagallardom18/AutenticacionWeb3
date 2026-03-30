package autenticacion;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import jakarta.servlet.annotation.WebServlet;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.sql.DataSource;
import java.io.IOException;

/**
 * Servlet que gestiona la recuperación y el cambio de contraseña.
 * Implementa un flujo de dos pasos: envío de OTP y actualización de credenciales.
 */
@WebServlet("/CambiarContrasenaServlet")
public class CambiarContrasenaServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    
    /**
     * Expresión para validar la seguridad de la contraseña:
     * - Al menos un número.
     * - Al menos una letra.
     * - Longitud exacta de 8 caracteres.
     */
    private static final String PASSWORD_REGEX = "^(?=.*[0-9])(?=.*[a-zA-Z]).{8}$";
    
    private UsuarioDAO usuarioDAO;
    private ConfigService configService; 

    @Override
    public void init() throws ServletException {
        try {
            // Inicialización de servicios mediante JNDI
            Context ctx = new InitialContext();
            DataSource ds = (DataSource) ctx.lookup("java:comp/env/jdbc/autenticacion");
            usuarioDAO = new UsuarioDAO(ds);
            configService = new ConfigService(ds); 
        } catch (Exception e) {
            throw new ServletException("Error inicializando servicios en CambiarContrasenaServlet", e);
        }
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String accion = request.getParameter("accion");

        if (accion == null) {
            response.sendRedirect("login.jsp");
            return;
        }

       
        switch (accion) {
            case "enviarOTP":
                enviarOTPRecuperacion(request, response);
                break;
            case "cambiarContrasena":
                cambiarContrasena(request, response);
                break;
            default:
                response.sendRedirect("login.jsp");
        }
    }

    
     //Valida el DNI y correo y envía un código OTP.
    private void enviarOTPRecuperacion(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String dni = request.getParameter("dni");
        String correo = request.getParameter("correo");

        // Validación de campos vacíos
        if (esNuloOVacio(dni) || esNuloOVacio(correo)) {
            mostrarError(request, response, "recuperarContrasena.jsp", "Todos los campos son obligatorios.");
            return;
        }

        // Verificación de existencia del usuario y si coinciden los datos
        Usuario usuario = usuarioDAO.obtenerUsuarioPorDNI(dni);
        if (usuario == null || !correo.equalsIgnoreCase(usuario.getCorreo())) {
            mostrarError(request, response, "recuperarContrasena.jsp", "Los datos introducidos no coinciden con nuestros registros.");
            return;
        }

        // Generación del código OTP
        String otp = Correo.generaOTP();
        HttpSession sesion = request.getSession(true);
        
        // Almacenamos la información en sesión para validarla en el siguiente paso
        sesion.setAttribute("recuperacion", true); // Flag para distinguir este flujo del login normal
        sesion.setAttribute("otpRecuperacion", otp);
        sesion.setAttribute("emailRecuperacion", correo);
        sesion.setAttribute("dniRecuperacion", dni);

        // Envío del correo electrónico con la configuración inyectada
        Correo.enviaCorreo(this.configService, correo, otp);

        // Redirigimos a la verificación
        response.sendRedirect("verificaOTP.jsp?origen=recuperacion");
    }

    
     //Valida la nueva contraseña y actualiza la base de datos.
    private void cambiarContrasena(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        HttpSession sesion = request.getSession(false);

        //Verifica que el usuario ha pasado por el envío de OTP previamente
        if (sesion == null || sesion.getAttribute("dniRecuperacion") == null 
            || sesion.getAttribute("recuperacion") == null) {
            response.sendRedirect("login.jsp");
            return;
        }

        String nuevaContrasena = request.getParameter("nuevaContrasena");
        String repetirContrasena = request.getParameter("repetirContrasena");
        String dni = (String) sesion.getAttribute("dniRecuperacion");

        if (esNuloOVacio(nuevaContrasena) || esNuloOVacio(repetirContrasena)) {
            mostrarError(request, response, "cambiarContrasena.jsp", "Debe completar ambos campos.");
            return;
        }

        // Validación de política de contraseñas
        if (!nuevaContrasena.matches(PASSWORD_REGEX)) {
            mostrarError(request, response, "cambiarContrasena.jsp", 
                "La contraseña debe tener 8 caracteres e incluir letras y números.");
            return;
        }

        // Validación de coincidencia de campos
        if (!nuevaContrasena.equals(repetirContrasena)) {
            mostrarError(request, response, "cambiarContrasena.jsp", "Las contraseñas no coinciden.");
            return;
        }

        try {
            Usuario usuario = usuarioDAO.obtenerUsuarioPorDNI(dni);
            if (usuario != null) {
                // Actualización en la BD
                usuarioDAO.actualizarContrasena(usuario.getCorreo(), nuevaContrasena);
                
                //Invalidar la sesión de recuperación por seguridad tras el éxito
                sesion.invalidate();
                
                request.setAttribute("mensaje", "Contraseña actualizada correctamente. Ya puede iniciar sesión.");
                request.getRequestDispatcher("login.jsp").forward(request, response);
            } else {
                response.sendRedirect("login.jsp");
            }
        } catch (Exception e) {
            mostrarError(request, response, "cambiarContrasena.jsp", "Error técnico al actualizar en la base de datos.");
        }
    }

    private boolean esNuloOVacio(String str) {
        return str == null || str.trim().isEmpty();
    }

    private void mostrarError(HttpServletRequest req, HttpServletResponse resp, String vista, String msg) 
            throws ServletException, IOException {
        req.setAttribute("error", msg);
        req.getRequestDispatcher(vista).forward(req, resp);
    }
}