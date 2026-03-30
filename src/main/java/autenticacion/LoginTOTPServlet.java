package autenticacion;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.sql.DataSource;

import java.io.IOException;


 // Servlet de inicio de sesión mediante códigos de aplicación (TOTP).
@WebServlet("/LoginTOTPServlet")
public class LoginTOTPServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private UsuarioDAO usuarioDAO;
    private ConfigService configService;

    @Override
    public void init() throws ServletException {
        try {
            // Inicialización de la conexión a BD y el servicio de configuración dinámica
            Context ctx = new InitialContext();
            DataSource ds = (DataSource) ctx.lookup("java:comp/env/jdbc/autenticacion");
            usuarioDAO = new UsuarioDAO(ds);
            configService = new ConfigService(ds);
        } catch (Exception e) {
            throw new ServletException("Error inicializando servicios en LoginTOTPServlet", e);
        }
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        // Captura de credenciales: DNI y el código de 6 dígitos de la App
        String dni = request.getParameter("dni");
        String totp = request.getParameter("totp");
        String modoLogin = request.getParameter("modoLogin"); // Puede ser "1FA" o "2FA"

        // Verifica que los datos no lleguen vacíos
        if (esVacio(dni) || esVacio(totp)) {
            mostrarError(request, response, "Debe introducir su DNI y el código de su App.");
            return;
        }

        // Buscamos al usuario en la base de datos por su DNI
        Usuario usuario = usuarioDAO.obtenerUsuarioPorDNI(dni);

        if (usuario == null) {
            mostrarError(request, response, "Identidad no reconocida.");
            return;
        }

        // Si el usuario no tiene un 'secret' guardado, no puede usar este método.
        if (esVacio(usuario.getTotpSecret())) {
            mostrarError(request, response, "Este usuario no tiene activado el factor TOTP.");
            return;
        }


        // Se compara el código introducido con el que debería generar el 'secret' en este instante de tiempo.
        boolean esValido = false;
        try {
            esValido = TOTPUtils.validarCodigo(usuario.getTotpSecret(), totp);
        } catch (Exception e) {
            e.printStackTrace();
            mostrarError(request, response, "Error al procesar el código.");
            return;
        }

        if (!esValido) {
            mostrarError(request, response, "Código incorrecto o caducado. Inténtelo de nuevo.");
            return;
        }

   
        HttpSession sesion = request.getSession(true);

        // Si solo se usa un único factor 
        if ("1FA".equals(modoLogin)) {
            sesion.setAttribute("usuario", dni);
            response.sendRedirect("bienvenido.jsp");
            return;
        }

        // Si hay dos factores
        if ("2FA".equals(modoLogin)) {
            String correo = usuario.getCorreo();
            if (esVacio(correo)) {
                mostrarError(request, response, "Error: No existe un correo asociado para el usuario.");
                return;
            }

            // Generamos un nuevo código OTP aleatorio para enviar por email
            String otp = Correo.generaOTP();
            sesion.setAttribute("usuarioTemp", dni); // Guardamos el DNI temporalmente
            sesion.setAttribute("otp", otp);

            // Enviamos el correo usando el servicio de configuración
            Correo.enviaCorreo(this.configService, correo, otp);

            // Redirigimos a la pantalla de verificación de email
            response.sendRedirect("verificaOTP.jsp");
            return;
        }

        // Manejo de error si el parámetro modoLogin no es válido
        mostrarError(request, response, "Configuración de seguridad no válida.");
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // Por seguridad, si intentan acceder por URL (GET), redirigimos al login
        response.sendRedirect("login.jsp");
    }

    //Comprueba si una cadena es nula o solo contiene espacios.
    private boolean esVacio(String s) {
        return s == null || s.trim().isEmpty();
    }

  
    private void mostrarError(HttpServletRequest req, HttpServletResponse resp, String msg) 
            throws ServletException, IOException {
        req.setAttribute("error", msg);
        req.getRequestDispatcher("login.jsp").forward(req, resp);
    }
}