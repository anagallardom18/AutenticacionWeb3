console.log("bienvenido.js cargado correctamente");

/**
 * UTILIDADES DE CONVERSIÓN (Unificadas para todos los métodos)
 */
function base64UrlToBytes(b64url) {
    const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(b64.padEnd(b64.length + (4 - b64.length % 4) % 4, '='));
    return Uint8Array.from(bin, c => c.charCodeAt(0));
}

function bufferToB64Url(buffer) {
    const bin = String.fromCharCode(...new Uint8Array(buffer));
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * 1. REGISTRO BIOMÉTRICO
 */
async function registrarBiometria(dni) {
    console.log("Iniciando registro biométrico...");
    try {
        // GET para obtener el reto
        const response = await fetch(`${contextPath}/RegistroBiometriaServlet?dni=${dni}`);
        if (!response.ok) throw new Error("Error al obtener opciones de biometría.");

        const options = await response.json();
        options.challenge = base64UrlToBytes(options.challenge);
        options.user.id = base64UrlToBytes(options.user.id);

        const credential = await navigator.credentials.create({ publicKey: options });

        const body = {
            id: credential.id,
            rawId: bufferToB64Url(credential.rawId),
            type: credential.type,
            response: {
                attestationObject: bufferToB64Url(credential.response.attestationObject),
                clientDataJSON: bufferToB64Url(credential.response.clientDataJSON)
            },
            dni: dni
        };

        // POST para guardar
        const guardar = await fetch(`${contextPath}/GuardaBiometriaServlet`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });

        if (guardar.ok) alert("Biometría registrada correctamente.");
        else alert("Error al guardar biometría.");
    } catch (err) {
        console.error(err);
        alert("Error: " + err.message);
    }
}

/**
 * 2. REGISTRO FIDO2 (Llaves físicas)
 */
async function registrarFIDO2(dni) {
    console.log("Iniciando registro FIDO2...");
    try {
        // GET al Servlet de Opciones (doGet)
        const resp = await fetch(`${contextPath}/OpcionesFido2Servlet?dni=${encodeURIComponent(dni)}`);
        if (!resp.ok) throw new Error("Error al obtener opciones FIDO2.");

        const options = await resp.json();
        options.challenge = base64UrlToBytes(options.challenge);
        options.user.id = base64UrlToBytes(options.user.id);

        const credential = await navigator.credentials.create({ publicKey: options });

        const body = {
            id: credential.id,
            rawId: bufferToB64Url(credential.rawId),
            type: credential.type,
            response: {
                attestationObject: bufferToB64Url(credential.response.attestationObject),
                clientDataJSON: bufferToB64Url(credential.response.clientDataJSON)
            },
            dni: dni
        };

        // POST al Servlet de Guarda (doPost)
        const guardarResp = await fetch(`${contextPath}/GuardaFido2Servlet`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });

        if (guardarResp.ok) alert("Dispositivo FIDO2 registrado correctamente.");
        else alert("Error al guardar FIDO2.");
    } catch (err) {
        console.error(err);
        alert("Error FIDO2: " + err.message);
    }
}

/**
 * 3. REGISTRO PASSKEY
 */
async function registrarPasskey(dni) {
    console.log("Iniciando registro de Passkey...");
    try {
        // GET al Servlet de Opciones (doGet) que ya tienes creado
        const res = await fetch(`${contextPath}/OpcionesPasskeyServlet?dni=${encodeURIComponent(dni)}`);
        if (!res.ok) {
            const msg = await res.text();
            throw new Error("Servidor respondió: " + msg);
        }

        const options = await res.json();
        options.challenge = base64UrlToBytes(options.challenge);
        options.user.id = base64UrlToBytes(options.user.id);

        const credential = await navigator.credentials.create({ publicKey: options });

        const body = {
            id: credential.id,
            rawId: bufferToB64Url(credential.rawId),
            type: credential.type,
            response: {
                attestationObject: bufferToB64Url(credential.response.attestationObject),
                clientDataJSON: bufferToB64Url(credential.response.clientDataJSON)
            },
            dni: dni
        };

        // POST al Servlet de Guarda (doPost)
        const guardarResp = await fetch(`${contextPath}/GuardaPasskeyServlet`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });

        if (guardarResp.ok) alert("Passkey registrada correctamente.");
        else alert("Error al guardar Passkey.");
    } catch (err) {
        console.error(err);
        alert("Error Passkey: " + err.message);
    }
}