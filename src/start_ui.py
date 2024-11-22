import streamlit as st
from model.signer.signer import Signer

AVAILABLE_KEY_SIZES = [512, 1024, 2048, 3072, 4096]


def init_config():
    if "signer" not in st.session_state:
        st.session_state.signer = Signer()


def render_generate_rsa_keys_tab():
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

            result = st.session_state.signer.generate_rsa_keys(
                pub_key_name, priv_key_name, key_size
            )

            st.success(
                f"Claves generadas:\n- Pública: {pub_key_name}\n- Privada: {priv_key_name}"
            )

    except Exception as e:
        st.error(f"Error generando claves: {e}")


def render_sign_file_tab():
    try:
        file = st.file_uploader("Sube el archivo a firmar")
        priv_key_file = st.file_uploader("Sube la llave privada")
        password = st.text_input("Contraseña de la llave privada", type="password")

        if st.button("Firmar archivo"):
            if not file or not priv_key_file or not password:
                st.error(
                    "Por favor, sube todos los archivos y proporciona la contraseña."
                )

                return

            signature = st.session_state.signer.sign_file(file, priv_key_file, password)

            st.success("Firma generada con éxito.")
            st.download_button("Descargar firma", signature, file_name="firma.sig")

    except Exception as e:
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

    </style>
    """,
        unsafe_allow_html=True,
    )

    st.markdown(
        "<h1 style='text-align: center;'>Firmador y Verificador de Firmas Digitales</h1>",
        unsafe_allow_html=True,
    )

    init_config()

    tabs = st.tabs(["Generar claves RSA", "Firmar archivo", "Verificar firma"])

    with tabs[0]:
        st.header("Generar claves RSA")
        render_generate_rsa_keys_tab()

    with tabs[1]:
        st.header("Firmar archivo")
        render_sign_file_tab()

    with tabs[2]:
        st.header("Verificar firma")
        render_verify_signature_tab()


if __name__ == "__main__":
    main()
