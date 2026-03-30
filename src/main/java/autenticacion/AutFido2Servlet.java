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
 * Servlet para la autenticación con llaves físicas FIDO2.
 * Verifica que la llave conectada al dispositivo pertenezca al usuario
 * y que la respuesta criptográfica sea válida para el desafío (challenge) actual.
 */
@WebServlet("/AutFido2Servlet")
public class AutFido2Servlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private final Gson gson = new Gson();
    private UsuarioDAO usuarioDAO;
    private ConfigService configService;

    @Override
    public void init() throws ServletException {
        try {
            // Configuración del acceso a datos y servicios de configuración
            Context ctx = new InitialContext();
            DataSource ds = (DataSource) ctx.lookup("java:comp/env/jdbc/autenticacion");
            usuarioDAO = new UsuarioDAO(ds);
            configService = new ConfigService(ds);
        } catch (Exception e) {
            throw new ServletException("Error inicializando servicios en FIDO2", e);
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        resp.setContentType("application/json");
        resp.setCharacterEncoding("UTF-8");

        HttpSession session = req.getSession(false);
        Map<String, Object> jsonResponse = new HashMap<>();

        try {
            // 1. VALIDACIÓN DE SESIÓN: Comprobar que existe un proceso de login iniciado
            if (session == null || session.getAttribute("webauthn_dni") == null) {
                enviarError(resp, 401, "Sesión expirada o no válida.");
                return;
            }

            String dniSesion = (String) session.getAttribute("webauthn_dni");
            String expectedChallenge = (String) session.getAttribute("webauthn_challenge");

            // 2. LECTURA DE DATOS: Obtener el JSON enviado por el navegador
            JsonObject json = gson.fromJson(req.getReader(), JsonObject.class);
            String dniJson = json.has("dni") ? json.get("dni").getAsString() : null;

            // Validar que el DNI que intenta autenticar coincide con el de la sesión
            if (dniJson == null || !dniJson.equals(dniSesion)) {
                enviarError(resp, 401, "El DNI no coincide con la sesión iniciada.");
                return;
            }

            JsonObject responseJson = json.getAsJsonObject("response");

            // 3. DECODIFICACIÓN: Transformar los strings de Base64 en bytes para procesarlos criptográficamente
            byte[] credentialId = decodificarBase64(json.get("rawId").getAsString());
            byte[] clientDataJSON = decodificarBase64(responseJson.get("clientDataJSON").getAsString());
            byte[] authenticatorData = decodificarBase64(responseJson.get("authenticatorData").getAsString());
            byte[] signature = decodificarBase64(responseJson.get("signature").getAsString());

            // 4. VERIFICACIÓN DEL CHALLENGE: Seguridad contra ataques de Replay
            // Se comprueba que el reto que firmó la llave es el mismo que el servidor generó hace unos segundos.
            JsonObject clientDataObj = gson.fromJson(new String(clientDataJSON, "UTF-8"), JsonObject.class);
            String receivedChallenge = clientDataObj.get("challenge").getAsString();
            if (expectedChallenge == null || !receivedChallenge.equals(expectedChallenge)) {
                enviarError(resp, 401, "El desafío de seguridad (challenge) ha caducado o es incorrecto.");
                return;
            }

            // 5. BÚSQUEDA DE CREDENCIAL: Obtener la clave pública de FIDO2 desde la tabla 'credenciales_fido2'
            UsuarioDAO.WebAuthnCredential cred = usuarioDAO.obtenerFido2(dniSesion, credentialId);
            if (cred == null) {
                enviarError(resp, 404, "Esta llave FIDO2 no está vinculada a su cuenta.");
                return;
            }

            // 6. VALIDACIÓN DE FIRMA: Comprobación matemática de la autenticidad
            boolean firmaOK = FirmaWeb.validarFirma(authenticatorData, clientDataJSON, signature, cred.getPublicKey());
            if (!firmaOK) {
                enviarError(resp, 401, "Firma de la llave FIDO2 incorrecta.");
                return;
            }

            // 7. ACTUALIZACIÓN DEL CONTADOR (Sign Count): Previene clones de llaves
            try {
                // El contador se encuentra en el offset 33 de la estructura de datos del autenticador
                int signCount = ByteBuffer.wrap(authenticatorData).getInt(33);
                usuarioDAO.actualizarSignCountFido2(dniSesion, credentialId, signCount);
            } catch (Exception e) {
                System.err.println("Aviso FIDO2: No se pudo actualizar el contador de uso.");
            }

            //8. LÓGICA DE LOGIN: Acceso directo o requiere código de correo
            String modoLogin = json.has("modoLogin") ? json.get("modoLogin").getAsString() : "1FA";

            if ("1FA".equals(modoLogin)) {
                //Autenticación completada con éxito
                session.setAttribute("usuario", dniSesion);
                jsonResponse.put("success", true);
                jsonResponse.put("redirect", "bienvenido.jsp");
            } else {
                // Paso adicional: Enviar OTP por correo electrónico
                Usuario usuario = usuarioDAO.obtenerUsuarioPorDNI(dniSesion);
                if (usuario == null || usuario.getCorreo() == null) {
                    enviarError(resp, 500, "Perfil de usuario incompleto para el envío de OTP.");
                    return;
                }

                String otp = Correo.generaOTP();
                session.setAttribute("otp", otp);
                session.setAttribute("usuarioTemp", dniSesion);
                
                // Envío del correo
                Correo.enviaCorreo(this.configService, usuario.getCorreo(), otp);

                jsonResponse.put("success", true);
                jsonResponse.put("requireOTP", true);
                jsonResponse.put("redirect", "verificaOTP.jsp");
            }

            resp.getWriter().write(gson.toJson(jsonResponse));

        } catch (Exception e) {
            e.printStackTrace();
            enviarError(resp, 500, "Error crítico en proceso FIDO2: " + e.getMessage());
        }
    }

    
     //Para decodificar Base64 de forma segura
    private byte[] decodificarBase64(String b64) {
        if (b64 == null) return new byte[0];
        try {
            return Base64.getUrlDecoder().decode(b64);
        } catch (IllegalArgumentException e) {
            return Base64.getDecoder().decode(b64);
        }
    }

   
     // Envío de error
    private void enviarError(HttpServletResponse resp, int code, String msg) throws IOException {
        resp.setStatus(code);
        Map<String, Object> error = new HashMap<>();
        error.put("success", false);
        error.put("message", msg);
        resp.getWriter().write(gson.toJson(error));
    }
}