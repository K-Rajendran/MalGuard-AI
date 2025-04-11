import os
import tempfile
import streamlit as st
from streamlit_lottie import st_lottie
from file_checker import checkFile
from streamlit_option_menu import option_menu
import json
from PIL import Image
import pyAesCrypt
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

#for loading the animations
def load_lottiefile(filepath: str):
    with open(filepath, "r") as f:
        return json.load(f)

st.set_page_config(
    page_title="Malware Detection",layout="wide", page_icon="", initial_sidebar_state="expanded"
)

# sidebar
with st.sidebar:

    st.markdown("<h1 style='text-align: center;'>📂MALWARE DETECTION</h1>", unsafe_allow_html=True)
    selected = option_menu('NAVIGATION', [
        'Malware Detection In Files',
        'AES Encryption/Decryption',
        'DES Encryption/Decryption',

    ],
        icons=['file-post','file-earmark-lock','folder-check'],
        menu_icon="house-heart-fill", default_index=0,
        styles={
            "icon": {"color": "orange", "font-size": "20px"}, 
            "nav-link": {"font-size": "17px", "text-align": "left", "margin":"0px", "--hover-color": "#eee"}
        }
    )
    st.sidebar.markdown('''<hr>''', unsafe_allow_html=True)
    st.sidebar.markdown("<h5 style='text-align: center;'>MALWARE DETECTION_WEBPAGE | March 2025 | JAI GANESH | RAJENDRAN</h3>", unsafe_allow_html=True)

#Malware detection page
if selected == 'Malware Detection In Files':
    st.markdown("<h1 style='text-align: left; color: #000080;'>MALWARE DETECTION IN A FILE USING RANDOM FOREST ALGORITHM</h1>", unsafe_allow_html=True)
    col1,col2 = st.columns((8,6))
    with col1:
        st.write(
            "Welcome to the Malware Detection application! This tool uses the Random Forest algorithm "
            "to analyze uploaded files and determine if they are likely to be legitimate or potential malware."
        )
        st.subheader("About the Algorithm:")
        st.markdown("The Random Forest algorithm is a machine learning algorithm that works by constructing a multitude "
                    "of decision trees at training time and outputs the class that is the mode of the classes (classification) "
                    "or the mean prediction (regression) of the individual trees.")
    with col2:
        lottie_pbc1 = load_lottiefile("lottiefiles/malware prevention.json")
        st_lottie(
            lottie_pbc1,
            loop=True,
            quality="high",
            height=330, width=400,
        )
    st.markdown("_________")
    st.subheader("How it Works:")
    st.write(
        "1. **Upload Files:** Use the file uploader to select one or more files for analysis. "
        "Supported file types include txt, pdf, png, jpg, jpeg, gif, and more."
    )
    st.write(
        "2. **Malware Detection:** The application will check each uploaded file for potential malware using a Random Forest model."
    )
    st.write(
        "3. **Results:** The tool will provide feedback on each file, indicating whether it seems legitimate or is suspected to be malware."
    )

    st.subheader("Instructions:")
    st.write(
        "1. Click on the 'Upload a file to check for malwares' button to select one or more files."
    )
    st.write(
        "2. Wait for the tool to process the files. You will see feedback for each file uploaded."
    )
    st.write(
        "3. The tool will indicate whether a file is considered legitimate or potentially malicious."
    )

    st.markdown("_________")
    st.subheader("Try yourself ^_^")

    files = st.file_uploader("Upload a file to check for malwares:", accept_multiple_files=True)
    if len(files):
        with st.spinner("Checking..."):
            st.write("### Malware Detection Results:")
            for file in files:
                try:
                    # Create a temporary file
                    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                        temp_file.write(file.getvalue())
                        temp_file_path = temp_file.name

                    # Check for malware
                    legitimate = checkFile(temp_file_path)

                    if legitimate:
                        st.success(f"File {file.name} seems *LEGITIMATE*!")
                        col1,col2 = st.columns((6,10))
                        with col2:
                            lottie_pbc1 = load_lottiefile("lottiefiles/virus scanning.json")
                            st_lottie(
                                lottie_pbc1,
                                loop=True,
                                quality="high",
                                height=280, width=280,
                            )
                    else:
                        st.error(f"File {file.name} is probably a **MALWARE**!!!")
                        col1,col2 = st.columns((6,10))
                        with col2:
                            lottie_pbc1 = load_lottiefile("lottiefiles/malwaredetected.json")
                            st_lottie(
                                lottie_pbc1,
                                loop=True,
                                quality="high",
                                height=280, width=280,
                            )
                except Exception as e:
                    st.error(f"An error occurred while checking {file.name}: {str(e)}")
                finally:
                    # Remove the temporary file
                    try:
                        os.remove(temp_file_path)
                    except Exception as e:
                        st.warning(f"Unable to remove the temporary file: {str(e)}")

    st.markdown("---")
    st.subheader("Note:")
    st.write(
        "Please keep in mind that this tool is not foolproof. It provides an analysis based on a Random Forest model, "
        "and false positives or negatives may occur. Use caution and additional tools for comprehensive security measures."
    )
    st.markdown("### Tips for Using the Malware Detection App")
    st.markdown("- Ensure you are uploading files of supported types (e.g., txt, pdf, png, jpg, jpeg, gif, .exe).")
    st.markdown("- If an error occurs during the check, it might be due to an unsupported file type or a technical issue.")
    st.markdown("- Delete the temporary files generated by the application for security and privacy reasons.")
    st.markdown("- Contact the administrator if you encounter persistent issues.")

    st.markdown("_________")
    st.markdown("For more details or assistance, please reach out to us.")

# Buffer size
BUFFER_SIZE = 65536

# Load Lottie animation from relative path
def load_lottiefile(filepath: str):
    with open(filepath, "r") as f:
        return json.load(f)

def encrypt(filepath, password, delfile):
    if not filepath:
        st.error("File Name cannot be empty!!")
    else:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".aes") as encrypted_file:
            encrypted_path = encrypted_file.name
        try:
            pyAesCrypt.encryptFile(filepath, encrypted_path, password, BUFFER_SIZE)
            if delfile:
                os.remove(filepath)
            st.success("File Encrypted Successfully!!")
            st.download_button("Download Encrypted File", open(encrypted_path, "rb").read(), file_name=os.path.basename(encrypted_path))
        except Exception:
            st.error("An error occurred!!")

def decrypt(filepath, password, delfile):
    if not filepath:
        st.error("File Name cannot be empty!!")
    else:
        # Ensure decrypted file doesn't overwrite input
        with tempfile.NamedTemporaryFile(delete=False) as decrypted_file:
            decrypted_path = decrypted_file.name
        try:
            pyAesCrypt.decryptFile(filepath, decrypted_path, password, BUFFER_SIZE)
            if delfile:
                os.remove(filepath)
            st.success("File Decrypted Successfully!!")
            st.download_button("Download Decrypted File", open(decrypted_path, "rb").read(), file_name=os.path.basename(decrypted_path))
        except ValueError as e:
            st.error(str(e))
        except Exception:
            st.error("An error occurred!!")

def main():
    col1, col2 = st.columns((4, 10))
    with col1:
        lottie_path = "lottiefiles/virus.json"
        if os.path.exists(lottie_path):
            lottie_pbc1 = load_lottiefile(lottie_path)
            st_lottie(lottie_pbc1, loop=True, quality="high", height=280, width=280)
    with col2:
        st.markdown("<h1 style='text-align: left; color: #000080;'>File Encrypter/Decrypter (AES Algorithm)</h1>", unsafe_allow_html=True)

    st.markdown("_________")

    uploaded_file = st.file_uploader("Select File:", type=["txt", "pdf", "png", "jpg", "jpeg", "gif", "aes"])
    password = st.text_input("Password", "12345", type="password")
    delfile = st.checkbox("Delete File after Encrypt/Decrypt", key="aeskey0")

    if uploaded_file is not None:
        # Save uploaded file to a temporary file
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(uploaded_file.getvalue())
            tmp_path = tmp.name

        if st.button("Encrypt"):
            encrypt(tmp_path, password, delfile)

        if st.button("Decrypt"):
            decrypt(tmp_path, password, delfile)

# Only run main if you're on the AES page
if selected == 'AES Encryption/Decryption':
    main()

def load_lottiefile(filepath: str):
    with open(filepath, "r") as f:
        return json.load(f)

def encrypt(filepath, key, delfile):
    try:
        with open(filepath, 'rb') as f:
            plaintext = f.read()
            cipher = DES.new(key, DES.MODE_ECB)
            ciphertext = cipher.encrypt(pad(plaintext, DES.block_size))

        encrypted_filepath = filepath + ".des"
        with open(encrypted_filepath, 'wb') as f:
            f.write(ciphertext)

        if delfile:
            os.remove(filepath)

        st.success("File Encrypted Successfully!")
        st.download_button("Download Encrypted File", open(encrypted_filepath, "rb").read(), file_name=os.path.basename(encrypted_filepath))
    except Exception as e:
        st.error(f"An error occurred: {str(e)}")

def decrypt(filepath, key, delfile):
    try:
        with open(filepath, 'rb') as f:
            ciphertext = f.read()
            cipher = DES.new(key, DES.MODE_ECB)
            plaintext = unpad(cipher.decrypt(ciphertext), DES.block_size)

        decrypted_filepath = filepath.replace(".des", "")
        with open(decrypted_filepath, 'wb') as f:
            f.write(plaintext)

        if delfile:
            os.remove(filepath)

        st.success("File Decrypted Successfully!")
        st.download_button("Download Decrypted File", open(decrypted_filepath, "rb").read(), file_name=os.path.basename(decrypted_filepath))
    except Exception as e:
        st.error(f"An error occurred: {str(e)}")

def main():
    col1, col2 = st.columns((4, 10))
    with col1:
        lottie_path = "lottiefiles/protection.json"
        if os.path.exists(lottie_path):
            lottie_pbc1 = load_lottiefile(lottie_path)
            st_lottie(
                lottie_pbc1,
                loop=True,
                quality="high",
                height=280,
                width=280,
            )
    with col2:
        st.markdown("<h1 style='text-align: left; color: #000080;'>File Encrypter/Decrypter (DES Algorithm)</h1>", unsafe_allow_html=True)

    st.markdown("_________")

    uploaded_file = st.file_uploader("Select File", type=["txt", "pdf", "png", "jpg", "jpeg", "gif", "des"])
    key_input = st.text_input("Key", type="password")
    key = key_input[:8].ljust(8, '0').encode('utf-8')  # Ensure key is 8 bytes

    delfile = st.checkbox("Delete File after Encrypt/Decrypt", key="deskey0")

    if uploaded_file is not None:
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(uploaded_file.getvalue())
            tmp_path = tmp.name

        if st.button("Encrypt File"):
            encrypt(tmp_path, key, delfile)

        if st.button("Decrypt File"):
            decrypt(tmp_path, key, delfile)

# Run only if on DES page
if selected == 'DES Encryption/Decryption':
    main()
