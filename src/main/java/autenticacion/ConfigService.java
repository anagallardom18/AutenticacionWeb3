package autenticacion;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;
import javax.sql.DataSource;

/**
 * Servicio de Configuración Dinámica.
 * Carga parámetros del sistema desde la tabla 'settings' de la base de datos y los mantiene en memoria (caché).
 */
public class ConfigService {
    
    // Diccionario en memoria para un acceso rápido a las configuraciones
    private final Map<String, String> settings = new HashMap<>();

    /**
     * realiza una lectura completa de la tabla 'settings'.
     * @param ds DataSource para obtener la conexión a la BD.
     */
    public ConfigService(DataSource ds) {
        String sql = "SELECT clave, valor FROM settings";
        
        // Uso de try-with-resources para asegurar el cierre de conexiones
        try (Connection con = ds.getConnection();
             PreparedStatement ps = con.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            
            while (rs.next()) {
                // Se vuelca cada fila de la BD al mapa interno 'settings'
                settings.put(rs.getString("clave"), rs.getString("valor"));
            }
            System.out.println("INFO: Configuración cargada correctamente desde la BD.");
            
        } catch (SQLException e) {
            e.printStackTrace();
            System.err.println("CRÍTICO: Error cargando configuración desde la tabla 'settings'.");
        }
    }

    
     //Obtiene un valor específico de configuración por su clave.
    public String getValue(String clave) {
        return settings.get(clave);
    }

 
     //Recupera el valor de una clave, permitiendo definir un respaldo.
    public String getOrDefault(String clave, String valorPorDefecto) {
        return settings.getOrDefault(clave, valorPorDefecto);
    }
}