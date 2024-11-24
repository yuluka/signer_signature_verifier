import streamlit as st
from model.signer.signer import Signer

import traceback

AVAILABLE_KEY_SIZES = [512, 1024, 2048, 3072, 4096]

AVAILABLE_SHA_ALGORITHMS = ["SHA1", "SHA256", "SHA512"]


def init_config():
    if "signer" not in st.session_state:
        st.session_state.signer = Signer()


def render_generate_rsa_keys_tab():
    """
    Render the tab to generate RSA keys.
    """

    try:
        st.write("<b>Nombres de las claves</b>", unsafe_allow_html=True)
        pub_key_name = st.text_input(
            label="Nombre para la llave pública",
            label_visibility="collapsed",
            placeholder="Nombre para la llave pública",
        )

        priv_key_name = st.text_input(
            label="Nombre para la llave privada",
            label_visibility="collapsed",
            placeholder="Nombre para la llave privada",
        )

        st.write("<b>Tamaño de la llave</b>", unsafe_allow_html=True)
        key_size = st.selectbox(
            label="Tamaño de la llave",
            label_visibility="collapsed",
            placeholder="Selecciona un tamaño para tu llave",
            options=AVAILABLE_KEY_SIZES,
            index=None,
        )

        st.write("<b>Protección de la llave</b>", unsafe_allow_html=True)
        password = st.text_input(
            label="Contraseña para proteger la llave privada",
            label_visibility="collapsed",
            placeholder="Digita una contraseña para proteger la llave privada",
            type="password",
        )

        if st.button(label="Generar llaves RSA", key="generate_rsa_keys"):
            if not pub_key_name or not priv_key_name or not password or not key_size:
                st.error("Por favor, completa todos los campos.")
                return

            keys_zip = st.session_state.signer.generate_rsa_keys(
                pub_key_name, priv_key_name, key_size, password
            )

            st.success(
                f"Claves generadas:\n- Pública: {pub_key_name}\n- Privada: {priv_key_name}"
            )

            st.download_button(
                label="Descargar llaves",
                data=keys_zip,
                file_name="llaves.zip",
                mime="application/zip",
            )

    except Exception as e:
        st.error(f"Error generando claves: {e}")


def render_unlock_private_key_tab():
    """
    Render the tab to unlock a private key.
    """

    try:
        st.write("<b>Sube tu llave privada</b>", unsafe_allow_html=True)
        priv_key_file = st.file_uploader(
            label="Sube la llave privada", label_visibility="collapsed"
        )

        st.write("<b>Contraseña de la llave</b>", unsafe_allow_html=True)
        password = st.text_input(
            label="Contraseña para desbloquear la llave privada",
            label_visibility="collapsed",
            placeholder="Digita la contraseña para desbloquear la llave privada",
            type="password",
        )

        if st.button(label="Desbloquear llave", key="unlock_rsa_keys"):
            if not password or not priv_key_file:
                st.error("Por favor, completa todos los campos.")
                return

            priv_key_file = priv_key_file.read()
            unlocked_key = st.session_state.signer.unlock_file_with_password(
                priv_key_file, password
            )

            st.success(f"Clave desbloqueada con éxito.")

            st.download_button(
                label="Descargar llaves",
                data=unlocked_key,
                file_name="private_key.pem",
            )

    except Exception as e:
        st.error(f"Error desbloquando clave: {e}")


def render_sign_file_tab():
    """
    Render the tab to sign a file.
    """

    try:
        st.write("<b>Sube el archivo que deseas firmar</b>", unsafe_allow_html=True)
        file = st.file_uploader(
            label="Sube el archivo a firmar", label_visibility="collapsed"
        )

        st.write("<b>Sube tu llave privada</b>", unsafe_allow_html=True)
        priv_key_file = st.file_uploader(
            label="Sube tu llave privada", label_visibility="collapsed"
        )

        st.write(
            "<b>Selecciona el algoritmo de Hash con el que deseas firmar</b>",
            unsafe_allow_html=True,
        )
        sha_algorithm: str = st.selectbox(
            label="Algoritmo de Hash",
            label_visibility="collapsed",
            placeholder="Selecciona un algoritmo de Hash",
            options=AVAILABLE_SHA_ALGORITHMS,
            index=None,
        )

        st.write("<b>Contraseña de la llave</b>", unsafe_allow_html=True)
        password = st.text_input(
            label="Contraseña para desbloquear la llave privada2",
            label_visibility="collapsed",
            placeholder="Digita la contraseña para desbloquear la llave privada",
            type="password",
        )

        if st.button("Firmar archivo", key="sign_file"):
            if not file or not priv_key_file or not password:
                st.error(
                    "Por favor, sube todos los archivos y proporciona la contraseña."
                )

                return

            file_name: str = file.name
            file = file.read()
            priv_key_file = priv_key_file.read()
            
            signature = st.session_state.signer.sign_file(
                file_name, file, priv_key_file, password, sha_algorithm
            )

            st.success("Firma generada con éxito.")
            st.download_button(
                label="Descargar firma", data=signature, file_name="firma.bin"
            )

    except Exception as e:
        traceback.print_exc()
        st.error(f"Error al firmar el archivo: {e}")


def render_verify_signature_tab():
    try:
        file = st.file_uploader("Sube el archivo original")
        signature_file = st.file_uploader("Sube el archivo de firma")
        pub_key_file = st.file_uploader("Sube la llave pública")

        if st.button("Verificar firma"):
            if not file or not signature_file or not pub_key_file:
                st.error("Por favor, sube todos los archivos necesarios.")
                return

            is_valid = st.session_state.signer.verify_signature(
                file, signature_file, pub_key_file
            )

            if is_valid:
                st.success("La firma es válida.")
            else:
                st.error("La firma no es válida.")

    except Exception as e:
        st.error(f"Error al verificar la firma: {e}")


def main():
    st.markdown(
        """
    <style>
    
    .st-key-generate_rsa_keys {
        width: 150px;
        margin-left: auto;
        margin-right: auto;
        margin-top: 20px;
    }

    .st-key-unlock_rsa_keys {
        width: 150px;
        margin-left: auto;
        margin-right: auto;
        margin-top: 20px;
    }

    .st-key-sign_file {
        width: 150px;
        margin-left: auto;
        margin-right: auto;
        margin-top: 20px;
    }

    </style>
    """,
        unsafe_allow_html=True,
    )

    st.markdown(
        "<h1 style='text-align: center;'>Firmador y Verificador de Firmas Digitales</h1>",
        unsafe_allow_html=True,
    )

    init_config()

    tabs = st.tabs(
        [
            "Generar claves RSA",
            "Desbloquear llave privada",
            "Firmar archivo",
            "Verificar firma",
        ]
    )

    with tabs[0]:
        st.header("Generar claves RSA")
        render_generate_rsa_keys_tab()

    with tabs[1]:
        st.header("Desbloquear llave privada")
        render_unlock_private_key_tab()

    with tabs[2]:
        st.header("Firmar archivo")
        render_sign_file_tab()

    with tabs[3]:
        st.header("Verificar firma")
        render_verify_signature_tab()


if __name__ == "__main__":
    main()
