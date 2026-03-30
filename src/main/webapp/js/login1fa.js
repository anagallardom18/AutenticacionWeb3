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

// Utilidad Base64
function base64UrlToBase64(b64url) {
    b64url = b64url.replace(/-/g, '+').replace(/_/g, '/');
    while (b64url.length % 4 !== 0) b64url += '=';
    return b64url;
}

// 🔹 BIOMETRIA (1FA)
document.getElementById('btnBiometria').addEventListener('click', async () => {
    try {
        const dni = document.getElementById('dniBiometria').value;
        if (!dni.trim()) return alert("Debes introducir un DNI.");

        const response = await fetch(`${contextPath}/OpcionesBiometriaServlet?dni=${encodeURIComponent(dni)}`);
        const options = await response.json();

        options.challenge = Uint8Array.from(atob(base64UrlToBase64(options.challenge)), c => c.charCodeAt(0));

        if (options.allowCredentials) {
            options.allowCredentials = options.allowCredentials.map(cred => ({
                ...cred,
                id: Uint8Array.from(atob(base64UrlToBase64(cred.id)), c => c.charCodeAt(0))
            }));
        }
        
        const credential = await navigator.credentials.get({ publicKey: options });

        const body = {
            modoLogin: "1FA",   
            id: credential.id,
            rawId: btoa(String.fromCharCode(...new Uint8Array(credential.rawId))),
            type: credential.type,
            response: {
                clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON))),
                authenticatorData: btoa(String.fromCharCode(...new Uint8Array(credential.response.authenticatorData))),
                signature: btoa(String.fromCharCode(...new Uint8Array(credential.response.signature)))
            }
        };

        const verifyResp = await fetch(`${contextPath}/AutBiometriaServlet`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });

        const result = await verifyResp.json();
        if(result.success){
            alert("Autenticación biométrica correcta.");
            window.location.href = "bienvenido.jsp";
        } else {
            alert("Error: " + result.message);
        }
    } catch(err) {
        alert("Error biometría: " + err);
    }
});

// 🔹 FIDO2 (1FA)
document.getElementById('btnFIDO2').addEventListener('click', async () => {
    try {
        const dni = document.getElementById('dniFIDO2').value;
        if (!dni.trim()) return alert("Debes introducir un DNI.");

        const response = await fetch(`${contextPath}/OpcionesFido2Servlet?dni=${encodeURIComponent(dni)}`);
        const options = await response.json();

        options.challenge = Uint8Array.from(atob(base64UrlToBase64(options.challenge)), c => c.charCodeAt(0));

        if (options.allowCredentials) {
            options.allowCredentials = options.allowCredentials.map(cred => ({
                ...cred,
                id: Uint8Array.from(atob(base64UrlToBase64(cred.id)), c => c.charCodeAt(0))
            }));
        }
        
        const credential = await navigator.credentials.get({ publicKey: options });

        const body = {
            modoLogin: "1FA",  
            id: credential.id,
            rawId: btoa(String.fromCharCode(...new Uint8Array(credential.rawId))),
            type: credential.type,
            response: {
                clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON))),
                authenticatorData: btoa(String.fromCharCode(...new Uint8Array(credential.response.authenticatorData))),
                signature: btoa(String.fromCharCode(...new Uint8Array(credential.response.signature)))
            },
            dni: dni
        };

        const verifyResp = await fetch(`${contextPath}/AutFido2Servlet`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });

        const result = await verifyResp.json();
        if(result.success){
            alert("Autenticación FIDO2 correcta.");
            window.location.href = "bienvenido.jsp";
        } else {
            alert("Error: " + result.message);
        }
    } catch(err) {
        alert("Error FIDO2: " + err);
    }
});

// 🔹 PASSKEY (1FA)
document.getElementById('btnPasskey').addEventListener('click', async () => {
    try {
        const dni = document.getElementById('dniPasskey').value;
        if (!dni.trim()) return alert("Debes introducir un DNI.");

        const response = await fetch(`${contextPath}/OpcionesPasskeyServlet?dni=${encodeURIComponent(dni)}`);
        const options = await response.json();

        options.challenge = Uint8Array.from(atob(base64UrlToBase64(options.challenge)), c => c.charCodeAt(0));

        if (options.allowCredentials) {
            options.allowCredentials = options.allowCredentials.map(cred => ({
                ...cred,
                id: Uint8Array.from(atob(base64UrlToBase64(cred.id)), c => c.charCodeAt(0))
            }));
        }
        
        const credential = await navigator.credentials.get({ publicKey: options });

        const body = {
            modoLogin: "1FA",  
            id: credential.id,
            rawId: btoa(String.fromCharCode(...new Uint8Array(credential.rawId))),
            type: credential.type,
            response: {
                clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON))),
                authenticatorData: btoa(String.fromCharCode(...new Uint8Array(credential.response.authenticatorData))),
                signature: btoa(String.fromCharCode(...new Uint8Array(credential.response.signature)))
            },
            dni: dni
        };

        const verifyResp = await fetch(`${contextPath}/AutPasskeyServlet`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });

        const result = await verifyResp.json();
        if(result.success){
            alert("Autenticación correcta.");
            window.location.href = "bienvenido.jsp";
        } else {
            alert("Error: " + result.message);
        }
    } catch(err) {
        alert("Error Passkey: " + err);
    }
});