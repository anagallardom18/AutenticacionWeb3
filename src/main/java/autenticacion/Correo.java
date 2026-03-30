package autenticacion;

import jakarta.mail.*;
import jakarta.mail.internet.*;
import java.util.Properties;
import java.security.SecureRandom; // Cambio: Más seguro que Random

public class Correo {

    // Genera un código de 6 dígitos de forma criptográficamente segura.
        public static String generaOTP() {
        SecureRandom sr = new SecureRandom();
        int codigo = 100000 + sr.nextInt(900000);
        return String.valueOf(codigo);
    }

    //Envía el correo usando la configuración dinámica de la BBDD.
    public static void enviaCorreo(ConfigService config, String destinatario, String otp) {

        // 1. Obtención de parámetros con valores por defecto para evitar NullPointerException
        final String remitente = config.getValue("email_user");
        final String appContrasena = config.getValue("email_password");
        final String host = config.getOrDefault("smtp_host", "smtp.gmail.com");
        final String port = config.getOrDefault("smtp_port", "587");

        // Validación de seguridad crítica
        if (remitente == null || appContrasena == null || remitente.isEmpty()) {
            System.err.println("ERROR: Configuración de correo incompleta en la tabla 'settings'.");
            return;
        }

        // 2. Configuración de propiedades con Timeouts (Evita que el hilo se quede colgado)
        Properties props = new Properties();
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.host", host);
        props.put("mail.smtp.port", port);
        
        // Timeouts de red (para que el servidor no se bloquee)
        props.put("mail.smtp.connectiontimeout", "5000"); // 5 segundos para conectar
        props.put("mail.smtp.timeout", "5000");           // 5 segundos para enviar

        // 3. Creación de la sesión
        Session session = Session.getInstance(props, new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(remitente, appContrasena);
            }
        });

        // 4. Construcción y envío del mensaje
        try {
            Message mensaje = new MimeMessage(session);
            mensaje.setFrom(new InternetAddress(remitente, "Sistema de Autenticación")); 
            mensaje.setRecipient(Message.RecipientType.TO, new InternetAddress(destinatario));
       
            mensaje.setSubject("Código de verificación: " + otp);
            
            StringBuilder sb = new StringBuilder();
            sb.append("Se ha solicitado un acceso a su cuenta. Su código de seguridad es:\n\n");
            sb.append(otp).append("\n\n");
            sb.append("Este código es de un solo uso.");
            
            mensaje.setText(sb.toString());

            Transport.send(mensaje);
            System.out.println("Correo enviado con éxito a: " + destinatario);

        } catch (Exception e) {
            System.err.println("Error en enviaCorreo: " + e.getMessage());
        }
    }
}