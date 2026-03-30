package autenticacion;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import jakarta.servlet.annotation.WebServlet;
import javax.naming.InitialContext;
import javax.naming.Context;
import javax.sql.DataSource;
import java.io.IOException;
import org.json.JSONObject;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.io.InputStream;

// Servlet de acceso corregido para evitar NullPointerException y errores de Maven
@WebServlet("/LoginServlet")
public class LoginServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private UsuarioDAO usuarioDAO;
    private ConfigService configService;

    @Override
    public void init() throws ServletException {
        try {
            // Inicialización de DAOs y servicios de configuración
            Context ctx = new InitialContext();
            DataSource ds = (DataSource) ctx.lookup("java:comp/env/jdbc/autenticacion");
            usuarioDAO = new UsuarioDAO(ds);
            configService = new ConfigService(ds);
        } catch (Exception e) {
            throw new ServletException("Error inicializando servicios en LoginServlet", e);
        }
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        // Recogida de parámetros del formulario y geolocalización del navegador
        String dni = request.getParameter("dni");
        String contrasena = request.getParameter("contrasena");
        String modoLogin = request.getParameter("modoLogin"); 
        String latitud = request.getParameter("latitud");
        String longitud = request.getParameter("longitud");

        // Validación básica de campos vacíos
        if (esVacio(dni) || esVacio(contrasena)) {
            mostrarError(request, response, "Rellene todos los campos.");
            return;
        }

        Usuario usuario = usuarioDAO.obtenerUsuarioPorDNI(dni);

        // Comprobación de usuario y contraseña
        if (usuario == null || !usuario.getContrasena().equals(contrasena)) {
            mostrarError(request, response, "DNI o contraseña incorrectos.");
            return;
        }

        // Se asegura de que el usuario siempre se conecte desde la misma IP autorizada
        String ipActual = getClientIp(request);
        if (esVacio(usuario.getIpPermitida())) {
            // Si es el primer login, se registra la IP actual como la permitida
            usuarioDAO.actualizarIpPermitida(dni, ipActual);
        } else if (!usuario.getIpPermitida().equals(ipActual)) {
            mostrarError(request, response, "Acceso denegado: IP no autorizada (" + ipActual + ").");
            return;
        }

        // Verifica que el usuario haya enviado su ubicación desde el navegador
        if (esVacio(latitud) || esVacio(longitud)) {
            mostrarError(request, response, "Debe permitir el acceso a la ubicación.");
            return;
        }

        try {
            double latActual = Double.parseDouble(latitud);
            double lonActual = Double.parseDouble(longitud);

            // CORRECCIÓN CRÍTICA: Usamos Double (objeto) para evitar NullPointerException
            Double latPermitida = usuario.getLatPermitida();
            Double lonPermitida = usuario.getLonPermitida();

            // Si los datos en la BD son NULL o 0, registramos la ubicación actual como "la permitida"
            if (latPermitida == null || lonPermitida == null || (latPermitida == 0 && lonPermitida == 0)) {
                usuarioDAO.actualizarUbicacionPermitida(dni, latActual, lonActual);
            } else {
                // Cálculo de distancia mediante la fórmula de Haversine
                double distancia = calcularDistancia(latActual, lonActual, latPermitida, lonPermitida);
                
                if (distancia > 20) { 
                    mostrarError(request, response, "Ubicación fuera de rango (" + String.format("%.2f", distancia) + " km).");
                    return;
                }
            }
        } catch (NumberFormatException e) {
            mostrarError(request, response, "Coordenadas inválidas.");
            return;
        }

        HttpSession sesion = request.getSession(true);

        if ("1FA".equals(modoLogin)) {
            // Acceso directo (1FA)
            sesion.setAttribute("usuario", dni);
            response.sendRedirect("bienvenido.jsp");
        } else {
            // Modo Segundo Factor: Envío de código OTP al correo
            String correo = usuario.getCorreo();
            if (esVacio(correo)) {
                mostrarError(request, response, "Correo no configurado.");
                return;
            }

            String otp = Correo.generaOTP();
            sesion.setAttribute("otp", otp);
            sesion.setAttribute("usuarioTemp", dni); 

            try {
                // Envío correo (Asegúrate de tener la dependencia 'angus-mail' en el pom.xml)
                Correo.enviaCorreo(this.configService, correo, otp);
            } catch (Exception e) {
                e.printStackTrace(); // Para ver errores de envío en la consola
                mostrarError(request, response, "Error al enviar el correo de verificación.");
                return;
            }

            // Registro histórico del acceso
            registrarGeolocalizacionIP(dni, ipActual);

            response.sendRedirect("verificaOTP.jsp");
        }
    }

    private void mostrarError(HttpServletRequest req, HttpServletResponse resp, String msg) 
            throws ServletException, IOException {
        req.setAttribute("error", msg);
        req.getRequestDispatcher("login.jsp").forward(req, resp);
    }

    private boolean esVacio(String s) {
        return s == null || s.trim().isEmpty();
    }

    private String getClientIp(HttpServletRequest request) {
        String xf = request.getHeader("X-Forwarded-For");
        return (xf != null && !xf.isEmpty()) ? xf.split(",")[0] : request.getRemoteAddr();
    }

    private JSONObject consultarIP(String ip) throws IOException {
        String urlStr = "http://ip-api.com/json/" + URLEncoder.encode(ip, StandardCharsets.UTF_8);
        URL url = URI.create(urlStr).toURL();
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setConnectTimeout(2000);
        try (InputStream in = con.getInputStream()) {
            return new JSONObject(new String(in.readAllBytes(), StandardCharsets.UTF_8));
        }
    }

    private void registrarGeolocalizacionIP(String dni, String ip) {
        new Thread(() -> {
            try {
                JSONObject json = consultarIP(ip);
                String pais = json.optString("country", "Desconocido");
                String ciudad = json.optString("city", "Desconocida");
                usuarioDAO.registrarAccesoIP(dni, ip, pais, ciudad);
            } catch (Exception ignored) {}
        }).start();
    }

    public static double calcularDistancia(double lat1, double lon1, double lat2, double lon2) {
        double R = 6371; // Radio de la Tierra en km
        double dLat = Math.toRadians(lat2 - lat1);
        double dLon = Math.toRadians(lon2 - lon1);
        double a = Math.sin(dLat / 2) * Math.sin(dLat / 2)
                + Math.cos(Math.toRadians(lat1)) * Math.cos(Math.toRadians(lat2))
                * Math.sin(dLon / 2) * Math.sin(dLon / 2);
        return R * (2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a)));
    }
}