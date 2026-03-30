package autenticacion;

import javax.sql.DataSource;
import java.sql.*;
import java.util.*;
import java.util.Base64;

/**
 * Clase de Acceso a Datos (DAO) para la gestión de usuarios y credenciales.
 * Centraliza todas las consultas SQL de la aplicación.
 */
public class UsuarioDAO {

    private final DataSource dataSource;

    /**
     * Constructor que recibe el Pool de conexiones (DataSource).
     */
    public UsuarioDAO(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    // =========================================================================
    // 1. GESTIÓN DE USUARIOS Y SESIÓN
    // =========================================================================

    /**
     * Recupera un objeto Usuario completo buscando por su clave primaria (DNI).
     * Incluye datos de perfil, secretos TOTP y parámetros de seguridad adaptativa.
     */
    public Usuario obtenerUsuarioPorDNI(String dni) {
        String sql = "SELECT dni, correo, contrasena, totp_secret, ip_permitida, lat_permitida, lon_permitida FROM usuarios WHERE dni=?";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, dni);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    Usuario usuario = new Usuario();
                    usuario.setDni(rs.getString("dni"));
                    usuario.setCorreo(rs.getString("correo"));
                    usuario.setContrasena(rs.getString("contrasena"));
                    usuario.setTotpSecret(rs.getString("totp_secret"));
                    usuario.setIpPermitida(rs.getString("ip_permitida"));
                    usuario.setLatPermitida((Double) rs.getObject("lat_permitida"));
                    usuario.setLonPermitida((Double) rs.getObject("lon_permitida"));
                    return usuario;
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }

    // =========================================================================
    // 2. MÉTODOS ESPECÍFICOS PARA BIOMETRÍA (webauthn_credentials)
    // =========================================================================

    /**
     * Busca una credencial biométrica específica mediante el DNI y el ID de la credencial.
     */
    public WebAuthnCredential obtenerBiometria(String dni, byte[] credentialId) {
        String sql = "SELECT public_key, sign_count FROM webauthn_credentials WHERE usuario_dni=? AND credential_id=?";
        return ejecutarConsultaCredencial(sql, dni, credentialId);
    }

    /**
     * Actualiza el contador de firmas para prevenir ataques de clonación en biometría.
     */
    public void actualizarSignCountBiometria(String dni, byte[] credentialId, long newCount) {
        String sql = "UPDATE webauthn_credentials SET sign_count=? WHERE usuario_dni=? AND credential_id=?";
        ejecutarUpdateSignCount(sql, newCount, dni, credentialId);
    }

    /**
     * Registra una nueva llave biométrica vinculada a un usuario.
     */
    public boolean guardarCredencialWebAuthn(Usuario usuario, byte[] credentialId, byte[] publicKey) {
        String sql = "INSERT INTO webauthn_credentials (usuario_dni, credential_id, public_key, sign_count) VALUES (?, ?, ?, 0)";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, usuario.getDni());
            ps.setBytes(2, credentialId);
            ps.setBytes(3, publicKey);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }
    
    /**
     * Lista todas las IDs de credenciales biométricas para que el navegador sepa cuáles solicitar.
     */
    public List<Map<String, Object>> listarBiometria(String dni) {
        List<Map<String, Object>> allowCreds = new ArrayList<>();
        String sql = "SELECT credential_id FROM webauthn_credentials WHERE usuario_dni=?";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, dni);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    byte[] credId = rs.getBytes("credential_id");
                    String idB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(credId);
                    Map<String, Object> c = new HashMap<>();
                    c.put("type", "public-key");
                    c.put("id", idB64);
                    allowCreds.add(c);
                }
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        return allowCreds;
    }

    // =========================================================================
    // 3. MÉTODOS ESPECÍFICOS PARA FIDO2 (credenciales_fido2)
    // =========================================================================

    /**
     * Recupera la clave pública y contador de una llave física FIDO2.
     */
    public WebAuthnCredential obtenerFido2(String dni, byte[] credentialId) {
        String sql = "SELECT public_key, sign_count FROM credenciales_fido2 WHERE dni=? AND credential_id=?";
        return ejecutarConsultaCredencial(sql, dni, credentialId);
    }

    /**
     * Actualiza el contador de uso de la llave física.
     */
    public void actualizarSignCountFido2(String dni, byte[] credentialId, long newCount) {
        String sql = "UPDATE credenciales_fido2 SET sign_count=? WHERE dni=? AND credential_id=?";
        ejecutarUpdateSignCount(sql, newCount, dni, credentialId);
    }

    /**
     * Inserta una nueva llave FIDO2 en la base de datos tras un registro exitoso.
     */
    public boolean guardarCredencialFido2(String dni, byte[] credentialId, byte[] publicKey) {
        String sql = "INSERT INTO credenciales_fido2 (dni, credential_id, public_key, sign_count) VALUES (?, ?, ?, 0)";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, dni);
            ps.setBytes(2, credentialId);
            ps.setBytes(3, publicKey);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }
    
    /**
     * Obtiene la lista de IDs de llaves FIDO2 registradas para el flujo de login.
     */
    public List<Map<String, Object>> listarFido2(String dni) {
        List<Map<String, Object>> allowCreds = new ArrayList<>();
        String sql = "SELECT credential_id FROM credenciales_fido2 WHERE dni=?";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, dni);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    byte[] credId = rs.getBytes("credential_id");
                    String idB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(credId);
                    Map<String, Object> c = new HashMap<>();
                    c.put("type", "public-key");
                    c.put("id", idB64);
                    allowCreds.add(c);
                }
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        return allowCreds;
    }

    // =========================================================================
    // 4. MÉTODOS ESPECÍFICOS PARA PASSKEY (passkeys)
    // =========================================================================

    /**
     * Obtiene los datos de una Passkey
     */
    public WebAuthnCredential obtenerPasskey(String dni, byte[] credentialId) {
        String sql = "SELECT public_key, sign_count, user_handle FROM passkeys WHERE dni=? AND credential_id=?";
        return ejecutarConsultaCredencial(sql, dni, credentialId);
    }

    /**
     * Actualiza el contador de firmas de la Passkey.
     */
    public void actualizarSignCountPasskey(String dni, byte[] credentialId, long newCount) {
        String sql = "UPDATE passkeys SET sign_count=? WHERE dni=? AND credential_id=?";
        ejecutarUpdateSignCount(sql, newCount, dni, credentialId);
    }

    /**
     * Guarda una nueva Passkey
     */
    public boolean guardarCredencialPasskey(String dni, byte[] credentialId, byte[] publicKey, byte[] userHandle, int signCount) {
        String sql = "INSERT INTO passkeys (dni, credential_id, public_key, user_handle, sign_count) VALUES (?, ?, ?, ?, ?)";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, dni);
            ps.setBytes(2, credentialId);
            ps.setBytes(3, publicKey);
            ps.setBytes(4, userHandle);
            ps.setInt(5, signCount);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }
    
    /**
     * Lista las Passkeys disponibles para el usuario.
     */
    public List<Map<String, Object>> listarPasskey(String dni) {
        List<Map<String, Object>> list = new ArrayList<>();
        String sql = "SELECT credential_id FROM passkeys WHERE dni=?";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, dni);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    byte[] credId = rs.getBytes("credential_id");
                    String idB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(credId);
                    Map<String, Object> c = new HashMap<>();
                    c.put("type", "public-key");
                    c.put("id", idB64);
                    list.add(c);
                }
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        return list;
    }

    // =========================================================================
    // 5. MÉTODOS PRIVADOS DE APOYO (REUTILIZACIÓN)
    // =========================================================================

    /**
     * Método genérico para ejecutar consultas de lectura de credenciales WebAuthn.
     * Gestiona dinámicamente si el campo user_handle existe en el ResultSet.
     */
    private WebAuthnCredential ejecutarConsultaCredencial(String sql, String dni, byte[] credentialId) {
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, dni);
            ps.setBytes(2, credentialId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    WebAuthnCredential cred = new WebAuthnCredential();
                    cred.setPublicKey(rs.getBytes("public_key"));
                    cred.setSignCount(rs.getLong("sign_count"));
                    
                    try {
                        ResultSetMetaData rsmd = rs.getMetaData();
                        for (int i = 1; i <= rsmd.getColumnCount(); i++) {
                            if ("user_handle".equalsIgnoreCase(rsmd.getColumnName(i))) {
                                cred.setUserHandle(rs.getBytes("user_handle"));
                            }
                        }
                    } catch (Exception e) {
                    	
                    }
                    
                    return cred;
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Método genérico para actualizar el contador de firmas (sign_count).
     */
    private void ejecutarUpdateSignCount(String sql, long count, String dni, byte[] id) {
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setLong(1, count);
            ps.setString(2, dni);
            ps.setBytes(3, id);
            ps.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    // =========================================================================
    // 6. OTROS MÉTODOS (TOTP, Registro, Ubicación)
    // =========================================================================

    /**
     * Actualiza el secreto compartido para la generación de códigos TOTP (Google Authenticator).
     */
    public boolean actualizarTotpSecret(Usuario usuario) {
        String sql = "UPDATE usuarios SET totp_secret=? WHERE dni=?";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, usuario.getTotpSecret());
            ps.setString(2, usuario.getDni());
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Inserta un nuevo usuario en la tabla principal durante el proceso de registro.
     */
    public boolean registrarUsuario(Usuario usuario) {
        String sql = "INSERT INTO usuarios (dni, correo, contrasena) VALUES (?, ?, ?)";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, usuario.getDni());
            ps.setString(2, usuario.getCorreo());
            ps.setString(3, usuario.getContrasena());
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            return false;
        }
    }

    /**
     * Modifica la contraseña del usuario (utilizado en el flujo de recuperación).
     */
    public void actualizarContrasena(String correo, String nuevaContrasena) {
        String sql = "UPDATE usuarios SET contrasena=? WHERE correo=?";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, nuevaContrasena);
            ps.setString(2, correo);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Actualiza la dirección IP permitida para el acceso del usuario.
     */
    public void actualizarIpPermitida(String dni, String ipPermitida) {
        String sql = "UPDATE usuarios SET ip_permitida=? WHERE dni=?";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, ipPermitida);
            ps.setString(2, dni);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Establece las coordenadas geográficas desde donde el usuario tiene permitido el acceso.
     */
    public void actualizarUbicacionPermitida(String dni, double lat, double lon) {
        String sql = "UPDATE usuarios SET lat_permitida=?, lon_permitida=? WHERE dni=?";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setDouble(1, lat);
            ps.setDouble(2, lon);
            ps.setString(3, dni);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException("Error actualizando ubicación", e);
        }
    }

    /**
     * Registra un historial de accesos con IP, país y ciudad para auditoría de seguridad.
     */
    public void registrarAccesoIP(String dni, String ip, String pais, String ciudad) {
        String sql = "INSERT INTO device_locations (usuario_dni, ip, ip_country, ip_city) VALUES (?, ?, ?, ?)";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, dni);
            ps.setString(2, ip);
            ps.setString(3, pais);
            ps.setString(4, ciudad);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    // =========================================================================
    // CLASE INTERNA PARA CREDENCIALES
    // =========================================================================

    /**
     * DTO interno para representar los datos criptográficos de una credencial WebAuthn.
     */
    public static class WebAuthnCredential {
        private byte[] publicKey; // Clave pública para verificar firmas
        private long signCount;   // Contador de firmas para seguridad
        private byte[] userHandle; // Identificador interno del usuario (opcional)

        public byte[] getPublicKey() { return publicKey; }
        public void setPublicKey(byte[] publicKey) { this.publicKey = publicKey; }
        public long getSignCount() { return signCount; }
        public void setSignCount(long signCount) { this.signCount = signCount; }
        public byte[] getUserHandle() { return userHandle; }
        public void setUserHandle(byte[] userHandle) { this.userHandle = userHandle; }
    }
}