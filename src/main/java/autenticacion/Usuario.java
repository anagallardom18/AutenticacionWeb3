package autenticacion;

import java.io.Serializable;

/**
 * Entidad que representa a un usuario en el sistema de autenticación adaptativa.
 * Implementa Serializable para permitir su almacenamiento en HttpSession si fuera necesario.
 */
public class Usuario implements Serializable {
    
    private static final long serialVersionUID = 1L;

    private int id;
    private String dni;
    private String contrasena;
    private String correo;
    
    // Atributos de Seguridad Adaptativa (Contexto)
    private String ipRegistro;   // IP utilizada en el primer registro
    private String ubicacion;    // Nombre de la ciudad/país (opcional)
    private String ipPermitida;  // IP de confianza actual
    private Double latPermitida; // Latitud GPS de confianza
    private Double lonPermitida; // Longitud GPS de confianza
    
    // Atributos de Segundo Factor (2FA)
    private String totpSecret;   // Secreto Base32 para Google Authenticator

    // Constructor vacío (Requerido para Java Beans / Frameworks)
    public Usuario() {}

    // --- MÉTODOS DE UTILIDAD LÓGICA ---

    /**
     * Indica si el usuario tiene activo el segundo factor por software (TOTP).
     */
    public boolean isTotpEnabled() {
        return totpSecret != null && !totpSecret.trim().isEmpty();
    }

    /**
     * Indica si el usuario tiene configurada una ubicación geográfica de confianza.
     */
    public boolean hasGeofencing() {
        return latPermitida != null && lonPermitida != null;
    }

  

    public int getId() { return id; }
    public void setId(int id) { this.id = id; }

    public String getDni() { return dni; }
    public void setDni(String dni) { this.dni = dni; }

    public String getContrasena() { return contrasena; }
    public void setContrasena(String contrasena) { this.contrasena = contrasena; }

    public String getCorreo() { return correo; }
    public void setCorreo(String correo) { this.correo = correo; }

    public String getIpRegistro() { return ipRegistro; }
    public void setIpRegistro(String ipRegistro) { this.ipRegistro = ipRegistro; }

    public String getUbicacion() { return ubicacion; }
    public void setUbicacion(String ubicacion) { this.ubicacion = ubicacion; }

    public String getIpPermitida() { return ipPermitida; }
    public void setIpPermitida(String ipPermitida) { this.ipPermitida = ipPermitida; }

    public Double getLatPermitida() { return latPermitida; }
    public void setLatPermitida(Double latPermitida) { this.latPermitida = latPermitida; }

    public Double getLonPermitida() { return lonPermitida; }
    public void setLonPermitida(Double lonPermitida) { this.lonPermitida = lonPermitida; }

    public String getTotpSecret() { return totpSecret; }
    public void setTotpSecret(String totpSecret) { this.totpSecret = totpSecret; }

   
    @Override
    public String toString() {
        return "Usuario{" + "id=" + id + ", dni='" + dni + '\'' + ", correo='" + correo + '\'' + '}';
    }
}