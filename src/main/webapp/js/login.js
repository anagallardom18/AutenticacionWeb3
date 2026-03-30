/**
 * Lógica de Autenticación Multimodal (Biometría, FIDO2, Passkey)
 * Diseñado para flujo 2FA
 */

/* global contextPath */

// Obtener ubicación al cargar
window.addEventListener("load", () => {
    if (!navigator.geolocation) {
        console.warn("Geolocalización no soportada");
        return;
    }

    navigator.geolocation.getCurrentPosition(
        pos => {
            document.getElementById("latitud").value = pos.coords.latitude;
            document.getElementById("longitud").value = pos.coords.longitude;
        },
        err => console.warn("Error ubicación:", err.message),
        { enableHighAccuracy: true, timeout: 10000, maximumAge: 0 }
    );
});

// 1. Utilidad para limpiar y convertir Base64URL a Base64 estándar
function base64UrlToBase64(b64url) {
    let b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4 !== 0) b64 += '=';
    return b64;
}

// 2. Función genérica para manejar la respuesta JSON de los Servlets
async function manejarRespuestaServidor(response) {
    if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.message || "Error en la comunicación con el servidor");
    }

    const result = await response.json();

    if (result.success) {
        alert("Paso 1 completado. Se ha enviado un código OTP a tu correo.");
        // Redirección dinámica basada en lo que responda el Servlet (verificaOTP.jsp)
        window.location.href = result.redirect || "verificaOTP.jsp";
    } else {
        alert("Error: " + (result.message || "Credencial no válida"));
    }
}

// --- LÓGICA BIOMETRÍA LOCAL ---
const btnBiometria = document.getElementById('btnBiometria');
if (btnBiometria) {
    btnBiometria.addEventListener('click', async () => {
        try {
            const dni = document.getElementById('dniBiometria').value;
            if (!dni.trim()) return alert("Por favor, introduce tu DNI.");

            // 1. Obtener opciones (Challenge)
            const respOp = await fetch(`${contextPath}/OpcionesBiometriaServlet?dni=${encodeURIComponent(dni)}`);
            if (!respOp.ok) throw new Error("No se pudieron obtener las opciones de biometría.");
            const options = await respOp.json();

            // 2. Preparar datos para WebAuthn API
            options.challenge = Uint8Array.from(atob(base64UrlToBase64(options.challenge)), c => c.charCodeAt(0));
            if (options.allowCredentials) {
                options.allowCredentials = options.allowCredentials.map(c => ({
                    ...c, id: Uint8Array.from(atob(base64UrlToBase64(c.id)), b => b.charCodeAt(0))
                }));
            }

            // 3. Solicitar firma al sensor (Huella/Rostro)
            const credential = await navigator.credentials.get({ publicKey: options });

            // 4. Construir body para el nuevo AutBiometriaServlet
            const body = {
                modoLogin: "2FA",
                dni: dni, // Enviamos el DNI para mayor seguridad
                rawId: btoa(String.fromCharCode(...new Uint8Array(credential.rawId))),
                response: {
                    clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON))),
                    authenticatorData: btoa(String.fromCharCode(...new Uint8Array(credential.response.authenticatorData))),
                    signature: btoa(String.fromCharCode(...new Uint8Array(credential.response.signature)))
                }
            };

            // 🔹 CAMBIO AQUÍ: Ahora apunta a AutBiometriaServlet
            const verifyResp = await fetch(`${contextPath}/AutBiometriaServlet`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            });

            await manejarRespuestaServidor(verifyResp);

        } catch(err) {
            console.error(err);
            alert("Error en la identificación biométrica: " + err.message);
        }
    });
}

// --- LÓGICA FIDO2 (LLAVES FÍSICAS) ---
const btnFIDO2 = document.getElementById('btnFIDO2');
if (btnFIDO2) {
    btnFIDO2.addEventListener('click', async () => {
        try {
            const dni = document.getElementById('dniFIDO2').value;
            if (!dni.trim()) return alert("DNI obligatorio para FIDO2.");

            const respOp = await fetch(`${contextPath}/OpcionesFido2Servlet?dni=${encodeURIComponent(dni)}`);
            const options = await respOp.json();

            options.challenge = Uint8Array.from(atob(base64UrlToBase64(options.challenge)), c => c.charCodeAt(0));
            if (options.allowCredentials) {
                options.allowCredentials = options.allowCredentials.map(c => ({
                    ...c, id: Uint8Array.from(atob(base64UrlToBase64(c.id)), b => b.charCodeAt(0))
                }));
            }

            const credential = await navigator.credentials.get({ publicKey: options });

            const body = {
                modoLogin: "2FA",
                dni: dni,
                rawId: btoa(String.fromCharCode(...new Uint8Array(credential.rawId))),
                response: {
                    clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON))),
                    authenticatorData: btoa(String.fromCharCode(...new Uint8Array(credential.response.authenticatorData))),
                    signature: btoa(String.fromCharCode(...new Uint8Array(credential.response.signature)))
                }
            };

            const verifyResp = await fetch(`${contextPath}/AutFido2Servlet`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            });

            await manejarRespuestaServidor(verifyResp);

        } catch(err) {
            alert("Error FIDO2: " + err.message);
        }
    });
}

// --- LÓGICA PASSKEY ---
const btnPasskey = document.getElementById('btnPasskey');
if (btnPasskey) {
    btnPasskey.addEventListener('click', async () => {
        try {
            const dni = document.getElementById('dniPasskey').value;
            if (!dni.trim()) return alert("DNI obligatorio para Passkey.");

            const respOp = await fetch(`${contextPath}/OpcionesPasskeyServlet?dni=${encodeURIComponent(dni)}`);
            const options = await respOp.json();

            options.challenge = Uint8Array.from(atob(base64UrlToBase64(options.challenge)), c => c.charCodeAt(0));
            if (options.allowCredentials) {
                options.allowCredentials = options.allowCredentials.map(c => ({
                    ...c, id: Uint8Array.from(atob(base64UrlToBase64(c.id)), b => b.charCodeAt(0))
                }));
            }

            const credential = await navigator.credentials.get({ publicKey: options });

            const body = {
                modoLogin: "2FA",
                dni: dni,
                rawId: btoa(String.fromCharCode(...new Uint8Array(credential.rawId))),
                response: {
                    clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON))),
                    authenticatorData: btoa(String.fromCharCode(...new Uint8Array(credential.response.authenticatorData))),
                    signature: btoa(String.fromCharCode(...new Uint8Array(credential.response.signature)))
                }
            };

            const verifyResp = await fetch(`${contextPath}/AutPasskeyServlet`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            });

            await manejarRespuestaServidor(verifyResp);

        } catch(err) {
            alert("Error Passkey: " + err.message);
        }
    });
}