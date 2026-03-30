package autenticacion;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.*;
import java.io.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.nio.ByteBuffer; // procesar datos binarios (signCount)

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.sql.DataSource;

import com.google.gson.*;

/**
 * Servlet encargado de la autenticación mediante Biometría (WebAuthn).
 * Recibe la firma criptográfica generada por el navegador y la valida contra la clave pública 
 * en la base de datos.
 */
@WebServlet("/AutBiometriaServlet")
public class AutBiometriaServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private final Gson gson = new Gson();
    private UsuarioDAO usuarioDAO;
    private ConfigService configService;

    @Override
    public void init() throws ServletException {
        try {
            // Inicialización de la conexión a JNDI y servicios de base de datos
            Context ctx = new InitialContext();
            DataSource ds = (DataSource) ctx.lookup("java:comp/env/jdbc/autenticacion");
            usuarioDAO = new UsuarioDAO(ds);
            configService = new ConfigService(ds); // Servicio para configuración de correo/servidor
        } catch (Exception e) {
            throw new ServletException("Error inicializando servicios en AutBiometriaServlet", e);
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        resp.setContentType("application/json");
        resp.setCharacterEncoding("UTF-8");

        HttpSession session = req.getSession(false);
        Map<String, Object> jsonResponse = new HashMap<>();

        try {
            // 1. Verificación de seguridad inicial: el DNI debe estar en sesión (procedente del Servlet de opciones)
            if (session == null || session.getAttribute("webauthn_dni") == null) {
                enviarError(resp, 401, "Sesión expirada o no válida.");
                return;
            }

            String dni = (String) session.getAttribute("webauthn_dni");
            
            // 2. Lectura del JSON enviado por el navegador (contiene el ID de credencial y la firma)
            JsonObject json = gson.fromJson(req.getReader(), JsonObject.class);
            JsonObject responseJson = json.getAsJsonObject("response");

            // 3. Decodificación de los datos binarios enviados por WebAuthn (Base64/Base64URL)
            byte[] credentialId = decodificarBase64(json.get("rawId").getAsString());
            byte[] clientDataJSON = decodificarBase64(responseJson.get("clientDataJSON").getAsString());
            byte[] authenticatorData = decodificarBase64(responseJson.get("authenticatorData").getAsString());
            byte[] signature = decodificarBase64(responseJson.get("signature").getAsString());

            // 4. Búsqueda de la clave pública guardada previamente en el registro
            UsuarioDAO.WebAuthnCredential cred = usuarioDAO.obtenerBiometria(dni, credentialId);
            if (cred == null) {
                enviarError(resp, 404, "Credencial biométrica no registrada para este usuario.");
                return;
            }

            // 5. VALIDACIÓN CRIPTOGRÁFICA: Comprobar que la firma es válida usando la clave pública
            boolean firmaOK = FirmaWeb.validarFirma(authenticatorData, clientDataJSON, signature, cred.getPublicKey());
            if (!firmaOK) {
                enviarError(resp, 401, "Firma biométrica inválida. Fallo de autenticación.");
                return;
            }

            // 6. Actualización del Contador de Firmas (Protección contra ataques de "replay")
            try {
                // El contador de firmas está en los bytes 33-37 del authenticatorData
                int signCount = ByteBuffer.wrap(authenticatorData).getInt(33);
                usuarioDAO.actualizarSignCountBiometria(dni, credentialId, signCount);
            } catch (Exception e) {
                System.err.println("Aviso: No se pudo actualizar el contador de firmas (opcional).");
            }

            // 7. Lógica de acceso: ¿Login directo o requiere Segundo Factor (OTP)?
            String modoLogin = json.has("modoLogin") ? json.get("modoLogin").getAsString() : "1FA";

            if ("1FA".equals(modoLogin)) {
                // Acceso directo: se establece el usuario en sesión
                session.setAttribute("usuario", dni);
                jsonResponse.put("success", true);
                jsonResponse.put("redirect", "bienvenido.jsp");
            } else {
                // Segundo Factor: Se genera y envía un código por correo
                Usuario usuario = usuarioDAO.obtenerUsuarioPorDNI(dni);
                if (usuario == null || usuario.getCorreo() == null) {
                    enviarError(resp, 500, "Error: No hay correo vinculado para el 2FA.");
                    return;
                }

                String otp = Correo.generaOTP();
                session.setAttribute("otp", otp);
                session.setAttribute("usuarioTemp", dni); // Usuario temporal hasta que valide el OTP
                
                // Envío de correo electrónico
                Correo.enviaCorreo(this.configService, usuario.getCorreo(), otp);

                jsonResponse.put("success", true);
                jsonResponse.put("requireOTP", true);
                jsonResponse.put("redirect", "verificaOTP.jsp");
            }

            resp.getWriter().write(gson.toJson(jsonResponse));

        } catch (Exception e) {
            e.printStackTrace();
            enviarError(resp, 500, "Error interno del servidor: " + e.getMessage());
        }
    }

    
     //Para decodificar Base64. 
    private byte[] decodificarBase64(String b64) {
        if (b64 == null) return new byte[0];
        try {
            return Base64.getUrlDecoder().decode(b64);
        } catch (IllegalArgumentException e) {
            return Base64.getDecoder().decode(b64);
        }
    }

    
     //Para enviar respuestas de error.
    private void enviarError(HttpServletResponse resp, int code, String msg) throws IOException {
        resp.setStatus(code);
        Map<String, Object> error = new HashMap<>();
        error.put("success", false);
        error.put("message", msg);
        resp.getWriter().write(gson.toJson(error));
    }
}