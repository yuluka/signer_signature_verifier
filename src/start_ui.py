import streamlit as st
from model.signer.signer import Signer

import traceback

AVAILABLE_KEY_SIZES = [512, 1024, 2048, 3072, 4096]

AVAILABLE_SHA_ALGORITHMS = ["SHA1", "SHA256", "SHA512"]


def init_config():
    if "signer" not in st.session_state:
        st.session_state.signer = Signer()

    if "custom_rsa_algorithm" not in st.session_state:
        st.session_state.custom_rsa_algorithm = False


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
                key="download_keys",
                data=keys_zip,
                file_name="llaves.zip",
                mime="application/zip",
            )

    except Exception as e:
        traceback.print_exc()
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
                label="Descargar llave",
                key="download_key",
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
                label="Descargar firma",
                key="download_signature",
                data=signature,
                file_name="firma.bin",
            )

    except Exception as e:
        traceback.print_exc()
        st.error(f"Error al firmar el archivo: {e}")


def render_verify_signature_tab():
    """
    Render the tab to verify a signature.
    """

    try:
        st.write("<b>Sube el archivo firmado</b>", unsafe_allow_html=True)
        file = st.file_uploader(
            label="Sube el archivo original", label_visibility="collapsed"
        )

        st.write("<b>Sube la firma generada</b>", unsafe_allow_html=True)
        signature_file = st.file_uploader(
            label="Sube el archivo de firma", label_visibility="collapsed"
        )

        st.write("<b>Sube la clave pública</b>", unsafe_allow_html=True)
        pub_key_file = st.file_uploader(
            label="Sube la llave pública", label_visibility="collapsed"
        )

        st.write(
            "<b>Selecciona el algoritmo de Hash con el que se generó la firma</b>",
            unsafe_allow_html=True,
        )
        sha_algorithm: str = st.selectbox(
            label="Algoritmo de Hash de la firma",
            label_visibility="collapsed",
            placeholder="Selecciona un algoritmo de Hash",
            options=AVAILABLE_SHA_ALGORITHMS,
            index=None,
        )

        if st.button("Verificar firma", key="verify_signature"):
            if not file or not signature_file or not pub_key_file or not sha_algorithm:
                st.error(
                    "Por favor, sube todos los archivos necesarios y selecciona un algoritmo de Hash."
                )
                return

            file_name: str = file.name
            file = file.read()
            signature_file = signature_file.read()
            pub_key_file = pub_key_file.read()

            is_valid = st.session_state.signer.verify_signature(
                file_name, file, signature_file, pub_key_file, sha_algorithm
            )

            if is_valid:
                st.success("La firma es válida.")
            else:
                st.error("La firma no es válida.")

    except Exception as e:
        st.error(f"Error al verificar la firma: {e}")


def custom_rsa_algorithm_swtch_callback():
    """
    Handle the change event of the custom RSA algorithm switch.

    When the switch is toggled, the custom RSA algorithm is enabled or disabled, and a toast message is shown.
    """
    if st.session_state.custom_rsa_algorithm:
        st.session_state.signer = Signer()
        st.toast(
            body="Algoritmo RSA personalizado deshabilitado.", icon=":material/tune:"
        )
    else:
        st.session_state.signer = Signer(True)
        st.toast(
            body="Algoritmo RSA personalizado habilitado.", icon=":material/brush:"
        )


def main():
    st.set_page_config(page_title="Firmador y Verificador de firmas", page_icon="🔐")

    st.markdown(
        """
        <style>
        
        .st-key-generate_rsa_keys  {
            width: 150px;
            margin-left: auto;
            margin-right: auto;
            margin-top: 20px;
        }

        .st-key-unlock_rsa_keys  {
            width: 150px;
            margin-left: auto;
            margin-right: auto;
            margin-top: 20px;
        }

        .st-key-unlock_rsa_keys  {
            width: 150px;
            margin-left: auto;
            margin-right: auto;
            margin-top: 20px;
        }

        .st-key-sign_file  {
            width: 150px;
            margin-left: auto;
            margin-right: auto;
            margin-top: 20px;
        }

        .st-key-verify_signature  {
            width: 150px;
            margin-left: auto;
            margin-right: auto;
            margin-top: 20px;
        }

        .st-key-download_keys  {
            width: 150px;
            margin-left: auto;
            margin-right: auto;
            margin-top: 20px;
        }

        .st-key-download_key  {
            width: 150px;
            margin-left: auto;
            margin-right: auto;
            margin-top: 20px;
        }

        .st-key-download_signature {
            width: 150px;
            margin-left: auto;
            margin-right: auto;
            margin-top: 20px;
        }

        .st-key-custom_rsa_algorithm_swtch {
            margin-left: auto;
            width: 32px;
        }

        </style>
        """,
        unsafe_allow_html=True,
    )

    st.session_state.custom_rsa_algorithm = st.toggle(
        label="Algoritmo RSA personalizado",
        label_visibility="collapsed",
        key="custom_rsa_algorithm_swtch",
        on_change=custom_rsa_algorithm_swtch_callback,
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
