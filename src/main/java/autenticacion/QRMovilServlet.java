package autenticacion;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import jakarta.servlet.annotation.WebServlet;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;

import com.google.zxing.*;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;
import java.util.HashMap;
import java.util.Map;

@WebServlet("/QRMovilServlet")
public class QRMovilServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        try {
            // 1. URL de destino (Túnel de ngrok para que el móvil acceda)
            String urlDestino = "https://comical-jamika-noninhabitable.ngrok-free.dev/AutenticacionWeb3/index.jsp";

            // 2. Configuración de renderizado del QR
            Map<EncodeHintType, Object> hints = new HashMap<>();
            hints.put(EncodeHintType.CHARACTER_SET, "UTF-8");
            hints.put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.M); // Margen de error medio
            hints.put(EncodeHintType.MARGIN, 1); // Borde blanco pequeño

            // 3. Generar el QR
            QRCodeWriter qrWriter = new QRCodeWriter();
            BitMatrix matrix = qrWriter.encode(urlDestino, BarcodeFormat.QR_CODE, 250, 250, hints);

            // 4. Convertir a imagen PNG en memoria
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            MatrixToImageWriter.writeToStream(matrix, "PNG", outputStream);

            // 5. Convertir a Base64 para el JSP
            String base64QR = Base64.getEncoder().encodeToString(outputStream.toByteArray());

            // 6. Pasar a la vista
            request.setAttribute("qrImage", "data:image/png;base64," + base64QR);
            request.setAttribute("urlGenerada", urlDestino); 

            request.getRequestDispatcher("mostrarQR.jsp").forward(request, response);
            
        } catch (Exception e) {
            e.printStackTrace();
            throw new ServletException("Error generando el código QR para acceso móvil", e);
        }
    }
}