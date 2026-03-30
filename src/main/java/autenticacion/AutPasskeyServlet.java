package autenticacion;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.*;
import java.io.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.nio.ByteBuffer;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.sql.DataSource;

import com.google.gson.*;

/**
 * Servlet para la autenticación mediante Passkeys.
 * Las Passkeys permiten un acceso sin contraseña basado en criptografía de clave pública,
 * gestionadas por el sistema operativo o gestores de contraseñas.
 */
@WebServlet("/AutPasskeyServlet")
public class AutPasskeyServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private final Gson gson = new Gson();
    private UsuarioDAO usuarioDAO;
    private ConfigService configService;

    @Override
    public void init() throws ServletException {
        try {
            // Inicialización de recursos JNDI y servicios de negocio
            Context ctx = new InitialContext();
            DataSource ds = (DataSource) ctx.lookup("java:comp/env/jdbc/autenticacion");
            usuarioDAO = new UsuarioDAO(ds);
            configService = new ConfigService(ds);
        } catch (Exception e) {
            throw new ServletException("Error inicializando servicios en AutPasskeyServlet", e);
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        resp.setContentType("application/json");
        resp.setCharacterEncoding("UTF-8");

        HttpSession session = req.getSession(false);
        Map<String, Object> jsonResponse = new HashMap<>();

        try {
            // 1. VALIDACIÓN DE CONTEXTO: Verificar que el usuario inició el flujo correctamente
            if (session == null || session.getAttribute("webauthn_dni") == null) {
                enviarError(resp, 401, "Sesión expirada o no válida.");
                return;
            }

            String dniSesion = (String) session.getAttribute("webauthn_dni");
            String expectedChallenge = (String) session.getAttribute("webauthn_challenge");

            // 2. PROCESAMIENTO DE LA PETICIÓN: Obtener el JSON de la Passkey
            JsonObject json = gson.fromJson(req.getReader(), JsonObject.class);
            String dniJson = json.has("dni") ? json.get("dni").getAsString() : null;

            // Validar que el DNI en la petición coincide con el DNI vinculado a la sesión
            if (dniJson == null || !dniJson.equals(dniSesion)) {
                enviarError(resp, 401, "DNI no autorizado para esta sesión de Passkey.");
                return;
            }

            JsonObject responseJson = json.getAsJsonObject("response");

            // 3. DECODIFICACIÓN DE DATOS WEBAUTHN:
            // rawId: ID único de la credencial Passkey.
            // clientDataJSON: Contiene el challenge y el origen (dominio).
            // authenticatorData: Datos del autenticador (incluye el contador de firmas).
            byte[] credentialId = decodificarBase64(json.get("rawId").getAsString());
            byte[] clientDataJSON = decodificarBase64(responseJson.get("clientDataJSON").getAsString());
            byte[] authenticatorData = decodificarBase64(responseJson.get("authenticatorData").getAsString());
            byte[] signature = decodificarBase64(responseJson.get("signature").getAsString());

            // 4. VERIFICACIÓN DEL DESAFÍO (CHALLENGE):
            // Para asegurar que la Passkey fue generada para esta petición específica y no reusada.
            JsonObject clientDataObj = gson.fromJson(new String(clientDataJSON, "UTF-8"), JsonObject.class);
            String receivedChallenge = clientDataObj.get("challenge").getAsString();
            if (expectedChallenge == null || !receivedChallenge.equals(expectedChallenge)) {
                enviarError(resp, 401, "Challenge de seguridad inválido o caducado.");
                return;
            }

            // 5. RECUPERACIÓN DE CLAVE PÚBLICA: Se busca en la tabla 'passkeys'
            UsuarioDAO.WebAuthnCredential cred = usuarioDAO.obtenerPasskey(dniSesion, credentialId);
            if (cred == null) {
                enviarError(resp, 404, "Passkey no encontrada o no vinculada a esta cuenta.");
                return;
            }

            // 6. VALIDACIÓN CRIPTOGRÁFICA DE LA FIRMA:
            // Se verifica que la Passkey firmó correctamente el reto usando la clave pública almacenada.
            boolean firmaOK = FirmaWeb.validarFirma(authenticatorData, clientDataJSON, signature, cred.getPublicKey());
            if (!firmaOK) {
                enviarError(resp, 401, "La firma de la Passkey es inválida.");
                return;
            }

            // 7. PROTECCIÓN CONTRA CLONACIÓN (Sign Count):
            // Actualizamos el contador de uso. Si el contador recibido es menor o igual al guardado, podría haber un clon.
            try {
                int signCount = ByteBuffer.wrap(authenticatorData).getInt(33);
                usuarioDAO.actualizarSignCountPasskey(dniSesion, credentialId, signCount);
            } catch (Exception e) {
                System.err.println("Aviso Passkey: No se pudo actualizar el contador de firmas.");
            }

            // 8. FINALIZACIÓN DEL LOGIN:
            String modoLogin = json.has("modoLogin") ? json.get("modoLogin").getAsString() : "1FA";

            if ("1FA".equals(modoLogin)) {
                // Acceso concedido directamente
                session.setAttribute("usuario", dniSesion);
                jsonResponse.put("success", true);
                jsonResponse.put("redirect", "bienvenido.jsp");
            } else {
                // Requiere segundo factor: OTP por correo
                Usuario usuario = usuarioDAO.obtenerUsuarioPorDNI(dniSesion);
                if (usuario == null || usuario.getCorreo() == null) {
                    enviarError(resp, 500, "Configuración de correo incompleta para el segundo factor.");
                    return;
                }

                String otp = Correo.generaOTP();
                session.setAttribute("otp", otp);
                session.setAttribute("usuarioTemp", dniSesion);
                
                // Envío de correo electrónico 
                Correo.enviaCorreo(this.configService, usuario.getCorreo(), otp);

                jsonResponse.put("success", true);
                jsonResponse.put("requireOTP", true);
                jsonResponse.put("redirect", "verificaOTP.jsp");
            }

            resp.getWriter().write(gson.toJson(jsonResponse));

        } catch (Exception e) {
            e.printStackTrace();
            enviarError(resp, 500, "Error técnico en el proceso de Passkey: " + e.getMessage());
        }
    }

   
     //Decodifica cadenas Base64  
    private byte[] decodificarBase64(String b64) {
        if (b64 == null) return new byte[0];
        try {
            return Base64.getUrlDecoder().decode(b64);
        } catch (IllegalArgumentException e) {
            return Base64.getDecoder().decode(b64);
        }
    }

   //Envía error
    private void enviarError(HttpServletResponse resp, int code, String msg) throws IOException {
        resp.setStatus(code);
        Map<String, Object> error = new HashMap<>();
        error.put("success", false);
        error.put("message", msg);
        resp.getWriter().write(gson.toJson(error));
    }
}